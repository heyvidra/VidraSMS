// SMS relay on Cloudflare Workers + D1.
//
// The phone POSTs exactly what it used to POST to ntfy, so the Android app needs no
// changes: POST /<topic>, Authorization: Bearer <SEND_TOKEN>, body = message text,
// Title header = sender (RFC 2047 encoded when it isn't plain ASCII).
//
// Reading the messages is a normal cookie session: /login issues an HMAC-signed cookie,
// every other read verifies it.

const PAGE_SIZE = 200;
// How long a claimed-but-unacked outbox row may sit before another poll may take it again.
// Longer than the 60s a send waits for its delivery report, plus room for a slow poll.
const CLAIM_TIMEOUT_MS = 5 * 60_000;
// After this many claims that never came back acked, stop re-queuing and mark the send failed —
// so a phone that can't submit (weak/roaming signal, ack never returns) can't leave it "发送中"
// forever. A real send acks within ~60s, well under one claim window, so a healthy send never
// reaches this.
const MAX_CLAIMS = 3;
const SESSION_DAYS = 30;

/* ---------------------------------------------------------------- primitives */

// Length is not secret; the comparison itself is what must not short-circuit.
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const b64url = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// Both credentials are part of the key material, so changing WEB_USER *or* WEB_PASS
// invalidates every outstanding session for free — no session store to expire. Leaving
// the username out would mean rotating it after a suspected compromise left the
// attacker's existing session working.
async function sign(env, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(`${env.SESSION_SECRET}:${env.WEB_USER}:${env.WEB_PASS}`),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return b64url(new Uint8Array(sig));
}

// The expiry is inside the signed payload, so it cannot be edited by the client.
async function issueSession(env) {
  const exp = String(Date.now() + SESSION_DAYS * 86400_000);
  return `${exp}.${await sign(env, exp)}`;
}

async function sessionValid(request, env) {
  if (!env.SESSION_SECRET || !env.WEB_PASS) return false;
  const cookie = request.headers.get("Cookie") || "";
  const m = /(?:^|;\s*)sms_session=([^;]+)/.exec(cookie);
  if (!m) return false;
  const [exp, sig] = decodeURIComponent(m[1]).split(".");
  if (!exp || !sig) return false;
  if (!safeEqual(sig, await sign(env, exp))) return false;
  return Number(exp) > Date.now();
}

const COOKIE_FLAGS = `Path=/; HttpOnly; Secure; SameSite=Strict`;

/* --------------------------------------------------------------- web push */

// Data-less Web Push: the server only holds ciphertext, so a push can't carry the code —
// it just wakes the PWA with "新验证码", and the app decrypts on open. That means no RFC 8291
// payload encryption is needed; only a VAPID (JWT) auth header per push service.
let _vapidKey = null;
async function vapidKey(env) {
  if (!_vapidKey) {
    _vapidKey = await crypto.subtle.importKey(
      "jwk", JSON.parse(env.VAPID_PRIVATE),
      { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
    );
  }
  return _vapidKey;
}
const b64uStr = (s) => b64url(new TextEncoder().encode(s));

async function vapidJwt(env, audience) {
  const header = b64uStr(JSON.stringify({ typ: "JWT", alg: "ES256" }));
  const payload = b64uStr(JSON.stringify({
    aud: audience, exp: Math.floor(Date.now() / 1000) + 43200, sub: env.VAPID_SUBJECT,
  }));
  // Web Crypto ECDSA returns the raw r||s that JWT ES256 expects (unlike Node's DER).
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, await vapidKey(env),
    new TextEncoder().encode(`${header}.${payload}`)
  );
  return `${header}.${payload}.${b64url(new Uint8Array(sig))}`;
}

async function pushAll(env) {
  if (!env.VAPID_PRIVATE || !env.VAPID_PUBLIC) return;
  const { results } = await env.DB.prepare("SELECT endpoint FROM subs").all();
  for (const row of results || []) {
    try {
      const jwt = await vapidJwt(env, new URL(row.endpoint).origin);
      const res = await fetch(row.endpoint, {
        method: "POST",
        headers: { Authorization: `vapid t=${jwt}, k=${env.VAPID_PUBLIC}`, TTL: "600" },
      });
      console.log("push", res.status, new URL(row.endpoint).host, (await res.clone().text().catch(() => "")).slice(0, 200));
      // A gone subscription (uninstalled PWA, expired) must be pruned or it errors forever.
      if (res.status === 404 || res.status === 410) {
        await env.DB.prepare("DELETE FROM subs WHERE endpoint = ?").bind(row.endpoint).run();
      }
    } catch { /* one bad endpoint shouldn't stop the rest */ }
  }
}

/* ------------------------------------------------------------------ publish */

// The phone encodes non-ASCII senders as =?UTF-8?B?<base64>?= because HttpURLConnection
// would otherwise mangle the header. Anything else is passed through as-is.
function decodeTitle(raw) {
  const s = (raw || "").trim();
  if (!s) return "unknown";
  const m = /^=\?UTF-8\?B\?([A-Za-z0-9+/=]+)\?=$/i.exec(s);
  if (!m) return s;
  try {
    const bytes = Uint8Array.from(atob(m[1]), (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes) || "unknown";
  } catch {
    return s;
  }
}

async function handlePublish(request, env, topic, ctx) {
  if (!env.SEND_TOKEN) return new Response("server not configured", { status: 500 });
  if (topic !== env.TOPIC) return new Response("unknown topic", { status: 404 });

  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ") || !safeEqual(auth.slice(7), env.SEND_TOKEN)) {
    return new Response("forbidden", { status: 403 });
  }

  const body = await request.text();
  if (!body) return new Response("empty body", { status: 400 });

  // A backfill (the app re-forwarding the phone's existing inbox) arrives with quiet=1 and the
  // message's ORIGINAL time: stored like any other row, but no push — 50 old messages must not
  // become 50 notifications — and timestamped when it really arrived, not when it was re-sent.
  const u = new URL(request.url);
  const quiet = u.searchParams.get("quiet") === "1";
  const tsParam = Number(u.searchParams.get("ts") || 0);
  const ts = (quiet && tsParam > 1e12 && tsParam <= Date.now() + 60_000) ? tsParam : Date.now();

  await env.DB.prepare("INSERT INTO messages (ts, sender, body) VALUES (?, ?, ?)")
    .bind(ts, decodeTitle(request.headers.get("Title")), body)
    .run();

  // A forward IS a heartbeat: on ColorOS/EMUI the phone's poll can be frozen while the SMS
  // broadcast still wakes it to deliver, so keying "online" only on the poll made an actively-
  // forwarding phone read offline. Bump its heartbeat here too. dev is the same opaque id the
  // poll already sends; ON CONFLICT so it works before the first devinfo creates the row.
  const dev = (u.searchParams.get("dev") || "").slice(0, 64);
  if (dev) {
    ctx?.waitUntil(env.DB.prepare(
      "INSERT INTO devices (id, ts) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET ts=excluded.ts"
    ).bind(dev, Date.now()).run());
  }

  // Notify subscribed PWAs after responding, so the phone's 200 isn't held up by push.
  if (!quiet) ctx?.waitUntil(pushAll(env));
  return new Response("ok", { status: 200 });
}

/* --------------------------------------------------------------------- read */

async function handleList(request, env) {
  const since = Number(new URL(request.url).searchParams.get("since") || 0);
  const { results } = await env.DB.prepare(
    "SELECT id, ts, sender, body FROM messages WHERE id > ? ORDER BY id DESC LIMIT ?"
  )
    .bind(Number.isFinite(since) ? since : 0, PAGE_SIZE)
    .all();
  return Response.json(results || []);
}

// DELETE /api/messages/<id>, or /api/messages/all to wipe everything.
async function handleDelete(env, rest) {
  // A web delete also removes the message from the phone's own SMS database. We can't do that from
  // the server (E2E: the number/body are only inside the encrypted blob, and only the default-SMS
  // phone can delete from the provider), so we copy the encrypted body into `deletions`; each phone
  // reads new rows on its next poll, decrypts, and deletes the matching SMS locally. Broadcast: any
  // phone with a copy deletes it, the rest find no match. Rows are pruned after a week (scheduled()).
  const now = Date.now();
  if (rest === "all") {
    const rows = await env.DB.prepare("SELECT body FROM messages").all();
    const stmts = (rows.results || []).map((r) =>
      env.DB.prepare("INSERT INTO deletions (ts, payload) VALUES (?, ?)").bind(now, r.body));
    stmts.push(env.DB.prepare("DELETE FROM messages"));
    await env.DB.batch(stmts);
    return Response.json({ ok: true, all: true });
  }
  const id = Number(rest);
  if (!Number.isInteger(id) || id <= 0) {
    return new Response('{"error":"bad id"}', {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
  const msg = await env.DB.prepare("SELECT body FROM messages WHERE id = ?").bind(id).first();
  if (msg) {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO deletions (ts, payload) VALUES (?, ?)").bind(now, msg.body),
      env.DB.prepare("DELETE FROM messages WHERE id = ?").bind(id),
    ]);
  }
  return Response.json({ ok: true, deleted: msg ? 1 : 0 });
}

async function handleLogin(request, env) {
  const form = await request.formData();
  const user = String(form.get("user") || "");
  const pass = String(form.get("pass") || "");

  if (!safeEqual(user, env.WEB_USER || "") || !safeEqual(pass, env.WEB_PASS || "")) {
    // Same message either way — never reveal which half was wrong. The delay makes
    // online guessing tedious without needing any state to rate-limit against.
    await new Promise((r) => setTimeout(r, 700));
    return new Response(loginPage("用户名或密码不正确"), {
      status: 401,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  const token = await issueSession(env);
  return new Response(null, {
    status: 303,
    headers: {
      Location: "/",
      "Set-Cookie": `sms_session=${token}; ${COOKIE_FLAGS}; Max-Age=${SESSION_DAYS * 86400}`,
    },
  });
}

/* ------------------------------------------------------------------- router */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const isRead = request.method === "GET" || request.method === "HEAD";

    // PWA plumbing (all public: manifest, service worker, icons, VAPID public key).
    if (isRead && path === "/manifest.json") {
      return new Response(MANIFEST, { headers: { "Content-Type": "application/manifest+json" } });
    }
    if (isRead && path === "/sw.js") {
      return new Response(SW, {
        headers: { "Content-Type": "application/javascript", "Service-Worker-Allowed": "/" },
      });
    }
    if (isRead && /^\/icon-(180|192|512)\.png$/.test(path)) {
      const png = await env.APK?.get(path.slice(1), "arrayBuffer");
      if (!png) return new Response("not found", { status: 404 });
      return new Response(png, {
        headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" },
      });
    }
    // Phone-prefix location table (public reference data, same as the icons). Stored already
    // gzipped — 659KB of runs becomes 253KB on the wire — and immutable, so the browser fetches
    // it once ever. The lookup itself runs in the page, so a number is never sent anywhere.
    if (isRead && path === "/pl.bin") {
      const bin = await env.APK?.get("phoneloc", "arrayBuffer");
      if (!bin) return new Response("not found", { status: 404 });
      // Deliberately NO Content-Encoding: declaring gzip made Cloudflare compress the already
      // gzipped body a second time, so the browser decoded one layer and got gzip bytes. Served
      // as opaque octet-stream the exact stored bytes arrive intact (any transfer compression in
      // between is transparent), and the page gunzips them itself.
      return new Response(bin, {
        headers: {
          "Content-Type": "application/octet-stream",
          "Cache-Control": "public, max-age=31536000, immutable",
        },
      });
    }
    if (isRead && path === "/api/vapid") {
      return new Response(env.VAPID_PUBLIC || "", { headers: { "Content-Type": "text/plain" } });
    }
    if (request.method === "POST" && path === "/api/subscribe") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const sub = await request.json().catch(() => null);
      if (!sub?.endpoint) return new Response('{"error":"bad"}', { status: 400 });
      await env.DB.prepare("INSERT OR REPLACE INTO subs (endpoint, p256dh, auth) VALUES (?, ?, ?)")
        .bind(sub.endpoint, sub.keys?.p256dh || "", sub.keys?.auth || "").run();
      return Response.json({ ok: true });
    }

    if (request.method === "POST" && path === "/api/unsubscribe") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const b = await request.json().catch(() => null);
      if (b?.endpoint) await env.DB.prepare("DELETE FROM subs WHERE endpoint = ?").bind(String(b.endpoint)).run();
      return Response.json({ ok: true });
    }

    // Fire a test push to every current subscription, so the user can verify push works without
    // waiting for a real SMS. pushAll also prunes any endpoint the push service reports as gone.
    if (request.method === "POST" && path === "/api/testpush") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const c = await env.DB.prepare("SELECT count(*) AS n FROM subs").first();
      await pushAll(env);
      return Response.json({ ok: true, subs: c?.n || 0 });
    }

    // --- outbound SMS queue ---------------------------------------------------------
    // Web enqueues an encrypted {to, body}; the phone (default SMS app) polls with its send
    // token, decrypts, sends, and acks. The server only ever holds ciphertext.
    if (request.method === "POST" && path === "/api/send") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const b = await request.json().catch(() => null);
      if (!b?.payload || typeof b.payload !== "string") return new Response('{"error":"bad"}', { status: 400 });
      // dev pins the send to one phone. Without it any phone may claim the row — fine with one
      // phone, wrong with two, where the message would go out over the other one's SIM.
      const dev = typeof b.dev === "string" && b.dev ? b.dev.slice(0, 64) : null;
      const r = await env.DB.prepare("INSERT INTO outbox (ts, payload, status, dev) VALUES (?, ?, 'pending', ?)")
        .bind(Date.now(), b.payload, dev).run();
      return Response.json({ ok: true, id: r.meta?.last_row_id });
    }
    // Web reads its own outbox to show status.
    if (isRead && path === "/api/outbox/list") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const { results } = await env.DB.prepare(
        "SELECT id, ts, payload, status, detail FROM outbox ORDER BY id DESC LIMIT 200"
      ).all();
      return Response.json(results || []);
    }
    // Phone pulls pending sends (bearer send-token, same as publishing). The phone hits this
    // every ~20s, so it doubles as the heartbeat. Two things happen atomically here:
    //  1. stamp last-seen (the web reads it to know the phone is alive);
    //  2. claim-on-read: flip pending -> sending and RETURN those rows, so if the phone's ack is
    //     lost after a real send, the row is no longer 'pending' and won't be sent a second time.
    if (isRead && path === "/api/outbox") {
      const auth = request.headers.get("Authorization") || "";
      if (!env.SEND_TOKEN || !auth.startsWith("Bearer ") || !safeEqual(auth.slice(7), env.SEND_TOKEN)) {
        return new Response("forbidden", { status: 403 });
      }
      // ?dev= identifies which phone is polling. Everything is keyed on it now, because with two
      // phones sharing one token a single heartbeat hid which one had died, and a send meant for
      // one could be claimed and sent by the other, off the wrong SIM.
      const dev = (url.searchParams.get("dev") || "").slice(0, 64);
      const now = Date.now();
      const stamp = dev
        ? env.DB.prepare("INSERT INTO devices (id, ts) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET ts=excluded.ts").bind(dev, now)
        : env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('beat', ?)").bind(String(now));
      // A claim that is never acked used to be terminal: the phone dies (or the response never
      // reaches it) right after the row flips to 'sending', and since nothing ever writes it back
      // the SMS is silently never sent. Rows stuck 'sending' past the timeout are returned to
      // 'pending' so the next poll picks them up. The window is generous — a real send waits up
      // to 60s for its delivery result — so a live phone is never second-guessed.
      // A claim stuck past the timeout: give it back to be retried — UNLESS it has already been
      // claimed MAX_CLAIMS times without ever acking, in which case the phone plainly can't submit
      // it (weak signal / lost acks) and it becomes 'failed' rather than cycling forever.
      const failout = env.DB.prepare(
        "UPDATE outbox SET status='failed', detail='多次尝试未送达（弱信号或网络问题）' " +
        "WHERE status='sending' AND ts <= ? AND claims >= ?"
      ).bind(now - CLAIM_TIMEOUT_MS, MAX_CLAIMS);
      const stale = env.DB.prepare(
        "UPDATE outbox SET status='pending' WHERE status='sending' AND ts <= ? AND claims < ?"
      ).bind(now - CLAIM_TIMEOUT_MS, MAX_CLAIMS);
      // A row addressed to a specific device is only ever claimed by that device; dev IS NULL
      // means "any phone", which is what a single-phone setup keeps producing. Each claim bumps
      // the counter that feeds the fail-out above.
      const claimSql = "UPDATE outbox SET status='sending', claims=claims+1 WHERE status='pending' AND (dev IS NULL OR dev = ?) RETURNING id, payload";
      const [, , , claim] = await env.DB.batch([
        stamp,
        failout,
        stale,
        env.DB.prepare(claimSql).bind(dev),
      ]);
      return Response.json(claim.results || []);
    }
    // Phone reports its name + SIM list, encrypted: both are PII, so the server keeps it opaque
    // and only the browser can read it. Per device, so two phones stop overwriting each other.
    if (request.method === "POST" && path === "/api/devinfo") {
      const auth = request.headers.get("Authorization") || "";
      if (!env.SEND_TOKEN || !auth.startsWith("Bearer ") || !safeEqual(auth.slice(7), env.SEND_TOKEN)) {
        return new Response("forbidden", { status: 403 });
      }
      const dev = (url.searchParams.get("dev") || "").slice(0, 64);
      if (!dev) return new Response('{"error":"bad"}', { status: 400 });
      const info = (await request.text()).slice(0, 4096);
      await env.DB.prepare(
        "INSERT INTO devices (id, ts, info) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET info=excluded.info"
      ).bind(dev, Date.now(), info).run();
      return Response.json({ ok: true });
    }
    // Web polls this for the per-device liveness list.
    if (isRead && path === "/api/status") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const { results } = await env.DB.prepare("SELECT id, ts, info FROM devices ORDER BY ts DESC").all();
      const legacy = await env.DB.prepare("SELECT v FROM meta WHERE k='beat'").first();
      return Response.json({ devices: results || [], beat: legacy ? Number(legacy.v) : 0 });
    }
    // Lets the web forget a phone that is gone for good, so a retired device stops showing as
    // permanently offline. It reappears on its own if that phone ever polls again.
    if (request.method === "POST" && path === "/api/device/forget") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const b = await request.json().catch(() => null);
      if (!b?.id) return new Response('{"error":"bad"}', { status: 400 });
      await env.DB.prepare("DELETE FROM devices WHERE id = ?").bind(String(b.id)).run();
      return Response.json({ ok: true });
    }
    // Phone reports the result of a send.
    if (request.method === "POST" && path === "/api/outbox/ack") {
      const auth = request.headers.get("Authorization") || "";
      if (!env.SEND_TOKEN || !auth.startsWith("Bearer ") || !safeEqual(auth.slice(7), env.SEND_TOKEN)) {
        return new Response("forbidden", { status: 403 });
      }
      const b = await request.json().catch(() => null);
      const id = Number(b?.id);
      if (!Number.isInteger(id)) return new Response('{"error":"bad"}', { status: 400 });
      await env.DB.prepare("UPDATE outbox SET status=?, detail=? WHERE id=?")
        .bind(b.ok ? "sent" : "failed", (b.detail || "").slice(0, 200), id).run();
      return Response.json({ ok: true });
    }


    // --- 定时保号 (keep-alive schedule) ------------------------------------------------
    // The browser stores a pre-encrypted 保号 SMS (the same v1: AES-GCM blob the compose flow
    // makes) plus when to fire it; the Cron Trigger (scheduled() below) re-queues that blob into
    // the outbox when due, and the phone drains it like any other send. Server stays blind to the
    // number/text. Disabled by default — nothing fires until the web switch turns it on.
    if (path === "/api/keepalive") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      if (isRead) {
        const row = await env.DB.prepare("SELECT v FROM meta WHERE k='keepalive'").first();
        return Response.json(row ? JSON.parse(row.v) : { enabled: false });
      }
      if (request.method === "POST") {
        const b = await request.json().catch(() => null);
        if (!b || typeof b.enabled !== "boolean") return new Response('{"error":"bad"}', { status: 400 });
        // When enabled, payload must be the v1: ciphertext the phone can decrypt.
        if (b.enabled && (typeof b.payload !== "string" || !b.payload.startsWith("v1:")))
          return new Response('{"error":"payload"}', { status: 400 });
        const cfg = {
          enabled: b.enabled,
          payload: typeof b.payload === "string" ? b.payload.slice(0, 4096) : "",
          dev: typeof b.dev === "string" && b.dev ? b.dev.slice(0, 64) : null,
          next: Number.isFinite(b.next) ? Math.floor(b.next) : 0,
          interval: Math.min(365, Math.max(1, Math.floor(Number(b.interval) || 30))),
          last: null,
        };
        // Preserve last-fire across edits.
        const prev = await env.DB.prepare("SELECT v FROM meta WHERE k='keepalive'").first();
        if (prev) { try { cfg.last = JSON.parse(prev.v).last ?? null; } catch {} }
        await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('keepalive', ?)").bind(JSON.stringify(cfg)).run();
        return Response.json({ ok: true });
      }
    }

    if (request.method === "POST" && path === "/login") return handleLogin(request, env);

    if (path === "/logout") {
      return new Response(null, {
        status: 303,
        headers: { Location: "/login", "Set-Cookie": `sms_session=; ${COOKIE_FLAGS}; Max-Age=0` },
      });
    }

    // In-app updater. The phone is already Bearer-authed (same SEND_TOKEN it uses for every
    // /api call), so it pulls the version + APK straight, bypassing the human download-code gate.
    // Additive: existing builds never call this, so shipping it changes nothing for them.
    //   GET /api/app?meta=1 -> {"code":<versionCode>,"name":"<versionName>"} (set by upload-apk.sh)
    //   GET /api/app        -> the APK bytes
    if (path === "/api/app") {
      const auth = request.headers.get("Authorization") || "";
      if (!env.SEND_TOKEN || !auth.startsWith("Bearer ") || !safeEqual(auth.slice(7), env.SEND_TOKEN)) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      if (new URL(request.url).searchParams.get("meta")) {
        const meta = await env.APK?.get("appmeta");
        return new Response(meta || '{"code":0,"name":""}', { headers: { "Content-Type": "application/json" } });
      }
      const apk = await env.APK?.get("app", "arrayBuffer");
      if (!apk) return new Response("APK not uploaded", { status: 404 });
      return new Response(apk, {
        headers: {
          "Content-Type": "application/vnd.android.package-archive",
          "Content-Length": String(apk.byteLength),
          "Cache-Control": "no-cache",
        },
      });
    }

    // Deletions the phone must mirror into its own SMS database. The phone reads rows past the
    // high-water mark it stored, decrypts each payload, and deletes the matching local SMS.
    if (path === "/api/deletions") {
      const auth = request.headers.get("Authorization") || "";
      if (!env.SEND_TOKEN || !auth.startsWith("Bearer ") || !safeEqual(auth.slice(7), env.SEND_TOKEN)) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const since = Number(new URL(request.url).searchParams.get("since") || "0") || 0;
      const rows = await env.DB.prepare(
        "SELECT id, payload FROM deletions WHERE id > ? ORDER BY id LIMIT 500"
      ).bind(since).all();
      return Response.json(rows.results || []);
    }

    // APK download, gated by a short code (not the full login). The APK embeds NTFY_TOKEN
    // and SMS_KEY, so this stops a random URL-guesser from grabbing it. Handled before the
    // publish catch-all so POST /app isn't mistaken for a phone upload. The code is checked
    // server-side against the APK_CODE secret — never exposed to the page.
    if (path === "/app" || path === "/c.apk") {
      if (request.method === "POST") {
        const form = await request.formData();
        if (env.APK_CODE && safeEqual(String(form.get("code") || ""), env.APK_CODE)) {
          const apk = await env.APK?.get("app", "arrayBuffer");
          if (!apk) return new Response("APK not uploaded", { status: 404 });
          return new Response(apk, {
            headers: {
              "Content-Type": "application/vnd.android.package-archive",
              "Content-Disposition": 'attachment; filename="app.apk"',
              "Content-Length": String(apk.byteLength),
              "Cache-Control": "no-cache",
            },
          });
        }
        await new Promise((r) => setTimeout(r, 600)); // slow down guessing
        return html(apkGatePage("下载码不正确"), 401);
      }
      if (isRead) return html(apkGatePage());
    }

    // Publish: any other POST is the phone. Checked before the session gate so a
    // browser cookie is never involved in forwarding.
    if (request.method === "POST" && path.length > 1) {
      return handlePublish(request, env, path.slice(1), ctx);
    }

    if (isRead && path === "/login") {
      if (await sessionValid(request, env)) {
        return new Response(null, { status: 303, headers: { Location: "/" } });
      }
      return html(loginPage());
    }

    // Deleting is session-only; SameSite=Strict on the cookie is what keeps another site
    // from triggering it, and the phone's token deliberately grants no read/delete rights.
    if (request.method === "DELETE" && path.startsWith("/api/messages/")) {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }
      return handleDelete(env, decodeURIComponent(path.slice("/api/messages/".length)));
    }

    // Same session-only guard: let the web clear an outbox row (a failed/stuck send it no longer
    // wants shown). The phone's send-token can't reach this.
    if (request.method === "DELETE" && path.startsWith("/api/outbox/")) {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', {
          status: 401, headers: { "Content-Type": "application/json" },
        });
      }
      const id = Number(decodeURIComponent(path.slice("/api/outbox/".length)));
      if (!Number.isInteger(id)) return new Response('{"error":"bad"}', { status: 400 });
      await env.DB.prepare("DELETE FROM outbox WHERE id = ?").bind(id).run();
      return Response.json({ ok: true });
    }

    if (isRead && (path === "/" || path === "/api/messages")) {
      if (!(await sessionValid(request, env))) {
        // The page redirects; the API answers 401 so the poller can react in JS.
        return path === "/"
          ? new Response(null, { status: 303, headers: { Location: "/login" } })
          : new Response('{"error":"unauthorized"}', {
              status: 401,
              headers: { "Content-Type": "application/json" },
            });
      }
      const res = path === "/" ? html(PAGE) : await handleList(request, env);
      return request.method === "HEAD"
        ? new Response(null, { status: res.status, headers: res.headers })
        : res;
    }

    return new Response("not found", { status: 404 });
  },

  // Cron Trigger (wrangler.toml [triggers]). Fires the 保号 keep-alive when due by queueing its
  // stored ciphertext into the outbox; the phone's normal ~20s poll drains it. No-op unless the
  // web switch enabled it and the chosen time has passed.
  async scheduled(event, env, ctx) {
    // Prune deletion rows older than a week — every phone polling within that window has seen them.
    await env.DB.prepare("DELETE FROM deletions WHERE ts < ?").bind(Date.now() - 7 * 86_400_000).run();
    // Backstop for stuck sends: the poll-path only fails a row out when a phone actually polls, so
    // a phone that goes offline mid-send leaves its row "发送中" forever. Fail any send still
    // sending well past the claim window (20-min grace lets a briefly-offline phone resume first).
    await env.DB.prepare(
      "UPDATE outbox SET status='failed', detail='发送未完成（手机离线/被杀），已超时' " +
      "WHERE status='sending' AND ts <= ?"
    ).bind(Date.now() - 20 * 60_000).run();
    const row = await env.DB.prepare("SELECT v FROM meta WHERE k='keepalive'").first();
    if (!row) return;
    let k; try { k = JSON.parse(row.v); } catch { return; }
    if (!k.enabled || !k.payload || !k.next) return;
    const now = Date.now();
    if (now < k.next) return;                         // not due yet
    // Advance past every missed window so a long outage (or long-disabled switch) fires once,
    // not a catch-up burst.
    const step = (k.interval || 30) * 86_400_000;
    let next = k.next + step;
    while (next <= now) next += step;
    k.next = next; k.last = now;
    // Queue + advance atomically (D1 batch is all-or-nothing): the send can't be inserted without
    // the schedule advancing, so a crash mid-way can't double-fire.
    await env.DB.batch([
      env.DB.prepare("INSERT INTO outbox (ts, payload, status, dev) VALUES (?, ?, 'pending', ?)")
        .bind(now, k.payload, k.dev || null),
      env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('keepalive', ?)").bind(JSON.stringify(k)),
    ]);
  },
};

function html(body, status = 200) {
  // no-store: the app HTML/JS changes often and there is no build hash on it, so without this a
  // browser can keep serving a stale page — new messages arrive via fetch but render with the old
  // code (e.g. missing the reply button). Cheap to always revalidate a single small document.
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

/* ---------------------------------------------------------------------- UI */

const STYLE = `
:root{
  color-scheme: light dark;
  --bg:#f6f7f9; --card:#fff; --ink:#11151c; --muted:#6b7280; --line:#e5e7eb;
  --accent:#2563eb; --accent-ink:#fff; --ring:rgba(37,99,235,.35);
  --fresh:#eff6ff; --fresh-line:#bfdbfe; --danger:#dc2626;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0e1116; --card:#161b22; --ink:#e6edf3; --muted:#8b949e; --line:#262c36;
    --accent:#3b82f6; --accent-ink:#fff; --ring:rgba(59,130,246,.4);
    --fresh:#12243d; --fresh-line:#1e4074; --danger:#f87171;
  }
}
*{box-sizing:border-box}
html{
  /* pan-y allows vertical scroll but blocks pinch-zoom and double-tap-zoom — this is what
     actually stops the gesture on iOS Safari, which ignores user-scalable=no. */
  touch-action:pan-y;
  -webkit-text-size-adjust:100%;   /* don't let the browser auto-inflate text */
}
body{
  margin:0; background:var(--bg); color:var(--ink); -webkit-font-smoothing:antialiased;
  touch-action:pan-y;
  font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
}
button{font:inherit}
`;

const LOGIN_CSS = `
.wrap{min-height:100dvh;display:grid;place-items:center;padding:24px}
.card{
  width:100%;max-width:360px;background:var(--card);border:1px solid var(--line);
  border-radius:16px;padding:32px 28px;box-shadow:0 1px 3px rgba(0,0,0,.04),0 12px 32px rgba(0,0,0,.06);
}
.mark{width:44px;height:44px;border-radius:12px;background:var(--accent);display:grid;place-items:center;margin-bottom:18px}
.mark svg{width:24px;height:24px;stroke:var(--accent-ink);fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
h1{font-size:19px;font-weight:650;margin:0 0 4px}
.sub{color:var(--muted);font-size:13.5px;margin:0 0 24px}
label{display:block;font-size:13px;font-weight:550;margin:0 0 6px}
input{
  width:100%;padding:11px 13px;margin-bottom:16px;border:1px solid var(--line);border-radius:10px;
  /* 16px is the threshold below which iOS Safari auto-zooms the page on focus — keep it here. */
  background:var(--bg);color:var(--ink);font-size:16px;transition:border-color .15s,box-shadow .15s;
}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--ring)}
.btn{
  width:100%;padding:11px;border:0;border-radius:10px;background:var(--accent);color:var(--accent-ink);
  font-weight:600;font-size:15px;cursor:pointer;transition:filter .15s;
}
.btn:hover{filter:brightness(1.08)}
.btn:active{filter:brightness(.94)}
.err{
  background:color-mix(in srgb,var(--danger) 10%,transparent);color:var(--danger);
  border:1px solid color-mix(in srgb,var(--danger) 30%,transparent);
  border-radius:9px;padding:9px 12px;font-size:13.5px;margin:0 0 18px;
}
`;

const loginPage = (error = "") => `<!doctype html>
<html lang="zh"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>登录 · 短信转发</title><style>${STYLE}${LOGIN_CSS}</style>
</head><body>
<div class="wrap"><form class="card" method="post" action="/login">
  <div class="mark"><svg viewBox="0 0 24 24"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></div>
  <h1>短信转发</h1>
  <p class="sub">请登录以查看转发的短信</p>
  ${error ? `<p class="err">${error}</p>` : ""}
  <label for="u">用户名</label>
  <input id="u" name="user" autocomplete="username" autocapitalize="off" autocorrect="off" required autofocus>
  <label for="p">密码</label>
  <input id="p" name="pass" type="password" autocomplete="current-password" required>
  <button class="btn" type="submit">登录</button>
</form></div>
</body></html>`;

// Small code gate in front of the APK download — reuses the login page styling.
const apkGatePage = (error = "") => `<!doctype html>
<html lang="zh"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>下载安装</title><style>${STYLE}${LOGIN_CSS}</style>
</head><body>
<div class="wrap"><form class="card" method="post" action="/app">
  <div class="mark"><svg viewBox="0 0 24 24"><path d="M12 3v12m0 0l4-4m-4 4l-4-4M5 21h14"/></svg></div>
  <h1>下载安装</h1>
  <p class="sub">输入下载码以获取安装包</p>
  ${error ? `<p class="err">${error}</p>` : ""}
  <label for="c">下载码</label>
  <input id="c" name="code" autocomplete="off" autocapitalize="off" autocorrect="off" required autofocus>
  <button class="btn" type="submit">下载</button>
</form></div>
</body></html>`;

// Service worker: shows a generic notification on push (server has no plaintext), and
// focuses the PWA on click.
const SW = `
// Activate a new SW version immediately — otherwise a fix sits waiting until every window is
// closed, and iOS keeps running the old handler.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(clients.claim()));

// --- tiny IndexedDB kv. A service worker cannot read localStorage, so the page mirrors the E2E
// key here (and only the key); the SW keeps its own read cursor (lastId) here too.
function idb(){ return new Promise((res, rej) => { const r = indexedDB.open("sms-sw", 1); r.onupgradeneeded = () => r.result.createObjectStore("kv"); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
async function kvGet(k){ try { const db = await idb(); return await new Promise((res) => { const t = db.transaction("kv").objectStore("kv").get(k); t.onsuccess = () => res(t.result); t.onerror = () => res(undefined); }); } catch { return undefined; } }
async function kvPut(k, v){ try { const db = await idb(); await new Promise((res) => { const t = db.transaction("kv", "readwrite"); t.objectStore("kv").put(v, k); t.oncomplete = () => res(); t.onerror = () => res(); }); } catch {} }

// --- decrypt: the same v1: AES-GCM blob the page opens. Done HERE, on the device, so the push
// can show real content while the server still only ever holds ciphertext.
function hexToBytes(h){ const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; }
async function openMsg(msg, key){
  if (!String(msg.body || "").startsWith("v1:")) return { sender: msg.sender, body: msg.body };
  if (!key) return null;
  try {
    const raw = Uint8Array.from(atob(msg.body.slice(3)), (c) => c.charCodeAt(0));
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12) }, key, raw.slice(12));
    const o = JSON.parse(new TextDecoder().decode(pt));
    return { sender: o.s, body: o.b };
  } catch { return null; }
}

// --- 号码归属地: same table + lookup as the page; the number never leaves the device.
let PLDB = null, AREA = null;
const CARD_NAME = { 1: "移动", 2: "联通", 3: "电信", 4: "电信虚拟", 5: "联通虚拟", 6: "移动虚拟", 7: "广电" };
function parsePL(bytes){
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]) !== "PL01") throw new Error("bad magic");
  let p = 4;
  const varint = () => { let v = 0, s = 1; for(;;){ const b = bytes[p++]; v += (b & 127) * s; if (!(b & 128)) break; s *= 128; } return v; };
  const recCount = dv.getUint16(p, true); p += 2;
  const dec = new TextDecoder();
  const records = new Array(recCount);
  for (let i = 0; i < recCount; i++){ const n = varint(); records[i] = dec.decode(bytes.subarray(p, p + n)); p += n; }
  const runCount = dv.getUint32(p, true); p += 4;
  const starts = new Int32Array(runCount), lens = new Int32Array(runCount), recs = new Int32Array(runCount), cards = new Uint8Array(runCount);
  let prev = 0;
  for (let i = 0; i < runCount; i++){ prev += varint(); starts[i] = prev; lens[i] = varint(); recs[i] = varint(); cards[i] = bytes[p++]; }
  return { records, starts, lens, recs, cards };
}
async function loadPL(){
  if (PLDB) return PLDB;
  try {
    const r = await fetch("/pl.bin", { cache: "force-cache" });
    if (!r.ok) return null;
    let bytes = new Uint8Array(await r.arrayBuffer());
    if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
      const ds = new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip")));
      bytes = new Uint8Array(await ds.arrayBuffer());
    }
    PLDB = parsePL(bytes);
    AREA = new Map();
    for (const rec of PLDB.records){ const f = rec.split("|"); if (f[3] && !AREA.has(f[3])) AREA.set(f[3], f[1] || f[0]); }
  } catch { return null; }
  return PLDB;
}
function plLookup(prefix){
  const s = PLDB.starts; let lo = 0, hi = s.length - 1, hit = -1;
  while (lo <= hi){ const mid = (lo + hi) >> 1; if (s[mid] <= prefix){ hit = mid; lo = mid + 1; } else hi = mid - 1; }
  if (hit < 0 || prefix >= s[hit] + PLDB.lens[hit]) return null;
  return { rec: PLDB.records[PLDB.recs[hit]], card: PLDB.cards[hit] };
}
function locOf(raw){
  if (!PLDB) return "";
  let d = String(raw || "").replace(/[^0-9]/g, "");
  if (d.length === 13 && d.slice(0, 2) === "86") d = d.slice(2);
  if (d.length >= 11 && d[0] === "1"){
    const hit = plLookup(Number(d.slice(0, 7))); if (!hit) return "";
    const f = hit.rec.split("|"); return (f[1] || f[0]) + " · " + (CARD_NAME[hit.card] || "");
  }
  if (d[0] === "0" && AREA) return AREA.get(d.slice(0, 4)) || AREA.get(d.slice(0, 3)) || "";
  return "";
}

// --- what to show for one decrypted message
//   未接来电  → "📞 未接来电"  /  号码 · 归属地
//   验证码    → 平台(【xx】或发件人) / 验证码 123456
//   其他      → 新消息 / 点击查看
const CODE_RE = /(^|[^0-9.])([0-9]{4,8})(?![0-9.])/;
function notifFor(m){
  const sender = String(m.sender || ""), body = String(m.body || "");
  if (body === "未接来电") {
    const loc = locOf(sender);
    return { title: "📞 未接来电", body: sender + (loc ? " · " + loc : "") };
  }
  const cm = CODE_RE.exec(body);
  if (cm) {
    const bm = /【([^】]{1,20})】/.exec(body);
    return { title: bm ? bm[1] : sender, body: "验证码 " + cm[2] };
  }
  return { title: "新消息", body: "点击查看" };
}

self.addEventListener("push", (e) => {
  e.waitUntil((async () => {
    const cls = await clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of cls) c.postMessage({ type: "sms" });   // an open page refetches at once
    const opts = { icon: "/icon-192.png", badge: "/icon-192.png" };
    let shown = 0;
    try {
      const hex = await kvGet("sms_key");
      const key = (typeof hex === "string" && /^[0-9a-f]{64}$/i.test(hex))
        ? await crypto.subtle.importKey("raw", hexToBytes(hex), "AES-GCM", false, ["decrypt"]) : null;
      const last = await kvGet("lastId");
      const r = await fetch("/api/messages?since=" + (last || 0), { credentials: "same-origin", cache: "no-store" });
      if (r.ok) {
        let rows = await r.json();                 // newest first
        if (!Array.isArray(rows)) rows = [];
        // First run has no cursor: show only the newest, or a fresh install fires one per stored row.
        if (!last && rows.length) rows = [rows[0]];
        rows.reverse();                            // oldest → newest so they read in order
        await loadPL().catch(() => null);
        let maxId = last || 0;
        for (const row of rows) {
          const m = await openMsg(row, key);
          const n = m ? notifFor(m) : { title: "新消息", body: "点击查看" };
          await self.registration.showNotification(n.title, Object.assign({ body: n.body, tag: "m" + row.id }, opts));
          shown++;
          if (row.id > maxId) maxId = row.id;
        }
        if (maxId !== (last || 0)) await kvPut("lastId", maxId);
      }
    } catch {}
    // ALWAYS show something: iOS revokes a subscription that gets a push with no notification.
    if (!shown) await self.registration.showNotification("新消息", Object.assign({ body: "点击查看", tag: "sms" }, opts));
  })());
});
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(clients.matchAll({ type: "window", includeUncontrolled: true }).then((cs) => {
    for (const c of cs) if ("focus" in c) return c.focus();
    return clients.openWindow("/");
  }));
});
`;

const MANIFEST = JSON.stringify({
  name: "验证码", short_name: "验证码", start_url: "/", scope: "/", display: "standalone",
  background_color: "#0e1116", theme_color: "#0e1116",
  icons: [
    { src: "/icon-192.png", sizes: "192x192", type: "image/png" },
    { src: "/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any maskable" },
  ],
});

const LIST_CSS = `
.top{
  position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:12px;
  padding:14px 20px;background:color-mix(in srgb,var(--bg) 82%,transparent);
  backdrop-filter:saturate(1.6) blur(12px);border-bottom:1px solid var(--line);
}
.top h1{font-size:15px;font-weight:650;margin:0;white-space:nowrap}
.dot{width:7px;height:7px;border-radius:50%;background:#22c55e;flex:none}
.dot.bad{background:var(--danger)}
.spacer{flex:1}
.out{
  border:1px solid var(--line);background:var(--card);color:var(--muted);
  padding:6px 12px;border-radius:8px;font-size:13px;cursor:pointer;text-decoration:none;
  /* Without these the header squeezes each button until its label wraps mid-word. Rare
     actions live behind ⋯ instead, so what stays out here always fits a phone width. */
  white-space:nowrap;flex:none;
}
.out.more{padding:6px 10px;font-size:15px;line-height:1}
/* Stacked full-width rows inside the ⋯ sheet. */
.out.wide{display:block;width:100%;text-align:center;padding:11px;margin-bottom:8px;font-size:14px}
.out:hover{color:var(--ink);border-color:var(--muted)}
main{max-width:760px;margin:0 auto;padding:20px}
ul{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:10px}
li{
  background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px;
  animation:in .35s cubic-bezier(.2,.8,.3,1);
  position:relative;   /* anchors .via, the bottom-right "which phone / which SIM" mark */
}
@keyframes in{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
li.fresh{background:var(--fresh);border-color:var(--fresh-line)}
/* gap 6, not 8: measured at 375px the worst row (11-digit number + 归属地 + SIM 标签 + 时间)
   needs exactly the full width, so the wider gap cost it the last 2px and clipped 归属地. */
.meta{display:flex;align-items:baseline;gap:6px;margin-bottom:5px}
.who{font-weight:650;font-size:14px;flex:none}
.when{color:var(--muted);font-size:12.5px;margin-left:auto;flex:none}
.simtag{font-size:10.5px;color:var(--muted);background:color-mix(in srgb,var(--muted) 14%,transparent);border-radius:5px;padding:1px 6px;font-weight:600;align-self:center;white-space:nowrap}
/* Which phone and which card, as a mark in the card's bottom-right rather than a pill on its own
   row. Faint enough to read as an annotation, and it takes no layout space at all. */
.via{position:absolute;right:14px;bottom:9px;font-size:12px;font-weight:600;color:var(--muted);opacity:.5;white-space:nowrap;pointer-events:none;max-width:60%;overflow:hidden;text-overflow:ellipsis}
/* Reserve the corner so a long message can't run underneath the mark. */
.body{padding-bottom:14px}
/* Second line under the sender: 归属地 and the SIM tag. They were in the meta row until the
   对话/✕ buttons left no width for them on a phone and 归属地 came out as "西…". */
/* Device liveness list. Name and status share a row (status pinned right, so a long phone name
   truncates instead of pushing it off); the SIM cards get their own line underneath. */
/* Devices sit in one horizontal strip: one row each pushed the messages down the screen, and
   with two or three phones the whole list was below the fold. Overflows sideways past that. */
.devstrip{display:flex;flex-direction:row;align-items:stretch;gap:8px;overflow-x:auto;margin:0 0 12px;padding-bottom:2px;scrollbar-width:none}
.devstrip::-webkit-scrollbar{display:none}
.dev{flex:none;max-width:230px;padding:6px 9px;border:1px solid var(--line);border-radius:9px;background:var(--card);cursor:pointer;display:flex;flex-direction:column}
.dev.on{border-color:var(--accent);box-shadow:0 0 0 2px var(--ring)}
.dev-top{display:flex;align-items:center;gap:6px}
.dev-name{font-size:12.5px;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dev-sub{display:flex;flex-direction:column;flex:1;margin-top:1px;font-size:10.5px;overflow:hidden}
.dev-state{font-weight:600}
.dev-sims{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dev-net{font-size:10.5px;color:var(--muted);opacity:.7;text-transform:uppercase;letter-spacing:.4px;font-weight:600;text-align:right;margin-top:auto}
/* The warning is the one line that must be readable in full — it is the reason you looked. It
   wraps instead of ellipsising, and the card widens a little to give it room. */
.dev-warn{color:var(--danger);font-weight:600;white-space:normal;line-height:1.35}
.dev-cap{color:#22c55e;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dev-all{flex:none;display:flex;align-items:center;padding:0 11px;border:1px dashed var(--line);border-radius:9px;font-size:11.5px;color:var(--muted);cursor:pointer;white-space:nowrap}
.dev-all.on{color:var(--accent);border-style:solid;border-color:var(--accent);font-weight:600;cursor:default}
.dev-top{display:flex;align-items:center;gap:7px}
.dev-name{font-size:13px;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0}
.dev-state{font-size:12px;font-weight:600;white-space:nowrap;flex:none}
.dev-sims{font-size:11.5px;color:var(--muted);margin-top:2px;padding-left:15px}
/* Footer row: version left, connection-type watermark right. baseline-aligned so "v1.5" and the
   network label sit on the same line at the card's bottom. */
.loc{font-size:11.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1 1 auto;min-width:0}
.body{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;font-size:14.5px}
.code{
  display:inline-block;font:600 15px/1.3 ui-monospace,SFMono-Regular,Menlo,monospace;
  letter-spacing:.06em;background:color-mix(in srgb,var(--accent) 12%,transparent);
  color:var(--accent);border-radius:6px;padding:1px 6px;cursor:pointer;
  border:1px solid color-mix(in srgb,var(--accent) 25%,transparent);
}
.code:hover{background:color-mix(in srgb,var(--accent) 20%,transparent)}
.code.done{background:color-mix(in srgb,#22c55e 18%,transparent);color:#16a34a;border-color:transparent}
.empty{text-align:center;color:var(--muted);padding:64px 0;font-size:14px}
.del{
  border:0;background:none;color:var(--muted);cursor:pointer;padding:2px 6px;border-radius:6px;
  font-size:15px;line-height:1;opacity:0;transition:opacity .15s,color .15s,background .15s;flex:none;
}
li:hover .del,li:focus-within .del{opacity:1}
.del:hover{color:var(--danger);background:color-mix(in srgb,var(--danger) 12%,transparent)}
@media (hover:none){.del{opacity:.55}}
/* Phones: keep the ONE compact row — stacking the cards full-width pushed the messages off the
   screen, which is the very thing the strip exists to avoid. Just make it discoverable that the
   row scrolls: the next card peeks past the right edge, and a slim scrollbar is shown (both were
   hidden before, so cards past the first looked like they didn't exist). */
@media (max-width:560px){
  main{padding:16px 12px}
  .dev{max-width:82vw}
  .devstrip{scrollbar-width:thin}
  .devstrip::-webkit-scrollbar{display:block;height:4px}
  .devstrip::-webkit-scrollbar-thumb{background:var(--line);border-radius:4px}
}
/* Pull-to-refresh indicator — parked just above the viewport, slid down by the drag. */
#ptr{
  position:fixed;left:0;right:0;top:0;height:46px;z-index:50;pointer-events:none;
  display:flex;align-items:center;justify-content:center;gap:7px;font-size:13px;color:var(--muted);
  transform:translateY(-46px);
}
#ptr .sp{width:15px;height:15px;border-radius:50%;border:2px solid var(--line);border-top-color:var(--accent);display:none;animation:ptrspin .7s linear infinite}
#ptr.load .sp{display:inline-block}
#ptr.load .tx{display:none}
@keyframes ptrspin{to{transform:rotate(360deg)}}
/* 「更多」as an anchored dropdown menu instead of a centered modal — positioned under the ⋯ button. */
.menu{
  position:fixed;z-index:60;min-width:150px;padding:6px;
  background:var(--card);border:1px solid var(--line);border-radius:12px;
  box-shadow:0 8px 28px rgba(0,0,0,.16);display:flex;flex-direction:column;gap:1px;
}
.menu[hidden]{display:none}
.mitem{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  width:100%;box-sizing:border-box;text-align:left;
  padding:10px 12px;border:0;border-radius:8px;background:none;color:var(--ink);
  font:inherit;font-size:14.5px;cursor:pointer;text-decoration:none;white-space:nowrap;
}
.mitem:hover,.mitem:focus-visible{background:color-mix(in srgb,var(--ink) 7%,transparent);outline:none}
.mitem.danger{color:var(--danger)}
.mitem .chk{color:var(--accent);font-weight:700}   /* right-aligned tick, e.g. 通知 已开启 */
.reply{
  border:0;background:none;color:var(--accent);cursor:pointer;flex:none;
  font-size:12.5px;font-weight:600;padding:2px 6px;border-radius:6px;line-height:1;
}
.reply:hover{background:color-mix(in srgb,var(--accent) 14%,transparent)}
/* chat / conversation view */
#threadDlg{max-width:520px}
.thead{display:flex;align-items:center;gap:10px;margin:-6px 0 12px}
.thead #threadName{font-size:16px;font-weight:700;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.thead button{border:0;background:none;color:var(--muted);cursor:pointer;font-size:18px;line-height:1;padding:4px 6px;border-radius:6px}
.thead button:hover{background:color-mix(in srgb,var(--muted) 15%,transparent)}
.thread-body{display:flex;flex-direction:column;gap:8px;max-height:56vh;overflow-y:auto;padding:4px 2px 2px}
.thread-empty{color:var(--muted);text-align:center;font-size:13px;padding:28px 0}
.bubble{max-width:80%;padding:8px 11px;border-radius:13px;font-size:14px;line-height:1.45;word-break:break-word;white-space:pre-wrap}
.bubble.inb{align-self:flex-start;background:var(--bg);border:1px solid var(--line);border-bottom-left-radius:4px}
.bubble.out{align-self:flex-end;background:var(--accent);color:#fff;border-bottom-right-radius:4px}
.bmeta{font-size:10.5px;opacity:.72;margin-top:3px}
.thread-input{display:flex;gap:8px;align-items:flex-end;margin-top:12px}
.thread-input select{flex:none;max-width:38%;padding:9px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font-size:16px}
.thread-input textarea{flex:1;padding:9px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font:16px/1.4 inherit;resize:none;max-height:120px}
.thread-input textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--ring)}
.thread-input .primary{flex:none}
.locked{
  background:color-mix(in srgb,var(--danger) 8%,transparent);
  border:1px dashed color-mix(in srgb,var(--danger) 35%,transparent);
  color:var(--muted);border-radius:10px;padding:10px 12px;font-size:13.5px;
}
dialog{
  border:1px solid var(--line);border-radius:16px;padding:24px;max-width:420px;width:calc(100% - 32px);
  background:var(--card);color:var(--ink);box-shadow:0 20px 50px rgba(0,0,0,.25);
}
dialog::backdrop{background:rgba(0,0,0,.45)}
dialog h2{font-size:16px;margin:0 0 6px}
dialog p{color:var(--muted);font-size:13.5px;margin:0 0 16px}
dialog input{
  width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);
  /* 16px avoids the iOS focus auto-zoom; keep the monospace look for the hex key. */
  color:var(--ink);font:16px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;margin-bottom:14px;
}
dialog input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--ring)}
.row{display:flex;gap:8px;justify-content:flex-end}
.row button{padding:9px 16px;border-radius:9px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer;font-size:14px}
.row button.primary{background:var(--accent);color:var(--accent-ink);border-color:transparent;font-weight:600}
`;

const PAGE = `<!doctype html>
<html lang="zh"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<link rel="manifest" href="/manifest.json">
<link rel="apple-touch-icon" href="/icon-180.png">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="验证码">
<meta name="theme-color" content="#0e1116">
<title>短信</title><style>${STYLE}${LIST_CSS}</style>
</head><body>
<header class="top">
  <span class="dot" id="dot"></span>
  <h1>短信转发</h1>
  <span class="spacer"></span>
  <button class="out" id="sendBtn" type="button">发短信</button>
  <button class="out" id="balBtn" type="button">话费</button>
  <button class="out more" id="moreBtn" type="button" aria-label="更多">⋯</button>
</header>

<div id="moreMenu" class="menu" hidden role="menu">
  <button class="mitem" id="notifyBtn" type="button" role="menuitem"><span>通知</span><span class="chk" hidden>✓</span></button>
  <button class="mitem" id="testPushBtn" type="button" role="menuitem"><span>测试推送</span></button>
  <button class="mitem" id="keyBtn" type="button" role="menuitem">密钥</button>
  <button class="mitem" id="kaBtn" type="button" role="menuitem">定时保号</button>
  <a class="mitem danger" href="/logout" role="menuitem">退出</a>
</div>
<main><div id="beat"></div><div id="kaStatus"></div><div id="outbox"></div><ul id="list"><li class="empty">加载中…</li></ul></main>

<dialog id="keyDlg">
  <h2>解密密钥</h2>
  <p>与手机 <code>local.properties</code> 里的 <code>SMS_KEY</code> 相同的 64 位十六进制。
     只保存在这台设备的浏览器里，不会上传。</p>
  <input id="keyInput" placeholder="64 位十六进制" spellcheck="false" autocomplete="off">
  <div class="row">
    <button type="button" id="keyClear">清除</button>
    <button type="button" id="keyCancel">取消</button>
    <button type="button" class="primary" id="keySave">保存</button>
  </div>
</dialog>

<dialog id="sendDlg">
  <h2 id="sendTitle">发短信</h2>
  <p>号码和内容会用你的密钥加密后排队，手机（默认短信 App）拉取后发出。服务器看不到明文。</p>
  <p id="sendHint" style="display:none;color:var(--accent);font-size:13px;margin:-6px 0 10px"></p>
  <div id="carrierWrap" style="display:none">
    <label style="display:block;font-size:13px;color:var(--muted);margin:-4px 0 6px">运营商（决定查询指令）</label>
    <select id="carrierSel"
      style="width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font-size:16px;margin-bottom:14px"></select>
  </div>
  <input id="sendTo" placeholder="收件号码" inputmode="tel" autocomplete="off">
  <textarea id="sendBody" placeholder="短信内容" rows="4"
    style="width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font-size:16px;margin-bottom:14px;resize:vertical"></textarea>
  <label style="display:block;font-size:13px;color:var(--muted);margin:-4px 0 6px">SIM 卡（双卡时选）</label>
  <select id="sendSim"
    style="width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font-size:16px;margin-bottom:14px">
    <option value="">默认卡</option>
    <option value="0">SIM 1</option>
    <option value="1">SIM 2</option>
  </select>
  <div class="row">
    <button type="button" id="sendCancel">取消</button>
    <button type="button" class="primary" id="sendGo">发送</button>
  </div>
</dialog>

<dialog id="kaDlg">
  <h2>定时保号</h2>
  <p>开启后，服务器按下面的时间把一条「查话费」短信排进队列，手机拉取后自动发出 —— 既算一次主动使用（防长期不用被销号），回复里还带余额。关闭则什么都不发。</p>
  <label style="display:flex;align-items:center;gap:8px;font-size:16px;margin-bottom:12px">
    <input type="checkbox" id="kaOn" style="width:18px;height:18px"> 启用定时保号
  </label>
  <div id="kaFields">
    <label style="display:block;font-size:13px;color:var(--muted);margin:-4px 0 6px">下次发送时间</label>
    <input type="datetime-local" id="kaWhen"
      style="width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font-size:16px;margin-bottom:14px">
    <label style="display:block;font-size:13px;color:var(--muted);margin:-4px 0 6px">每隔几天重复一次</label>
    <input type="number" id="kaEvery" min="1" max="365" value="30" inputmode="numeric"
      style="width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font-size:16px;margin-bottom:14px">
    <label style="display:block;font-size:13px;color:var(--muted);margin:-4px 0 6px">SIM 卡（要保的那张）</label>
    <select id="kaSim"
      style="width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font-size:16px;margin-bottom:6px"></select>
    <p id="kaHint" style="color:var(--accent);font-size:13px;margin:0 0 10px"></p>
  </div>
  <div class="row">
    <button type="button" id="kaCancel">取消</button>
    <button type="button" class="primary" id="kaSave">保存</button>
  </div>
</dialog>

<dialog id="threadDlg">
  <div class="thead">
    <span id="threadName"></span>
    <button type="button" id="threadClose" aria-label="关闭">✕</button>
  </div>
  <div id="threadBody" class="thread-body"></div>
  <div class="thread-input">
    <select id="threadSim" title="SIM 卡"></select>
    <textarea id="threadText" rows="1" placeholder="输入短信…"></textarea>
    <button type="button" class="primary" id="threadSend">发送</button>
  </div>
</dialog>
<script>
// iOS (all browsers are WebKit) ignores user-scalable=no, so block the zoom gestures in JS.
["gesturestart","gesturechange","gestureend"].forEach(t =>
  document.addEventListener(t, e => e.preventDefault(), { passive: false }));
document.addEventListener("touchmove", e => { if (e.touches.length > 1) e.preventDefault(); }, { passive: false });

const list = document.getElementById("list");
const dot  = document.getElementById("dot");
let maxId = 0, unread = 0, first = true;

// Client-side conversation store. Everything is grouped by phone number here, after decryption —
// the server never sees a number, so this grouping can only happen in the browser.
const INBOX = new Map();  // id -> {id, ts, number, sender, body}
let SENT = [];            // [{id, ts, number, to, body, status, detail}]
const norm = (x) => String(x || "").replace(/[^0-9+]/g, "");  // [0-9] not \\d — template-safe

function when(ms){
  const d = new Date(ms), diff = (Date.now() - ms) / 1000;
  if (diff < 60)   return "刚刚";
  if (diff < 3600) return Math.floor(diff / 60) + " 分钟前";
  const today = new Date().toDateString() === d.toDateString();
  const hm = String(d.getHours()).padStart(2,"0") + ":" + String(d.getMinutes()).padStart(2,"0");
  return today ? hm : (d.getMonth()+1) + "/" + d.getDate() + " " + hm;
}

// Verification codes are the whole point of this page, so make them one tap to copy.
// The lookarounds keep decimals intact: without them "余额12345.67元" highlights "12345"
// and leaves a stray ".67", which reads like a code and mangles the amount.
function renderBody(el, text){
  // No lookbehind: Safari only shipped it in 16.4, and an unsupported group is a SyntaxError at
  // parse time — it would take down the entire page script, not just the code highlighting.
  // The leading boundary is captured instead and re-emitted, which is equivalent here.
  const re = /(^|[^0-9.])([0-9]{4,8})(?![0-9.])/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) el.append(text.slice(last, m.index));
    if (m[1]) el.append(m[1]);   // the boundary char is context, not part of the code
    const b = document.createElement("span");
    b.className = "code";
    b.textContent = m[2];
    b.title = "点击复制";
    b.onclick = async () => {
      try {
        await navigator.clipboard.writeText(b.textContent);
        b.classList.add("done");
        setTimeout(() => b.classList.remove("done"), 1200);
      } catch {
        // Clipboard access needs a focused document and a secure context, and is refused
        // outright in some browsers. Select the digits instead so Cmd/Ctrl+C still works,
        // rather than leaving the tap looking broken.
        const r = document.createRange();
        r.selectNodeContents(b);
        const sel = getSelection();
        sel.removeAllRanges();
        sel.addRange(r);
      }
    };
    el.append(b);
    last = m.index + m[0].length;
    re.lastIndex = last;   // the consumed boundary must not hide a code that starts right after
  }
  el.append(text.slice(last));   // append, never innerHTML — SMS is untrusted input
}

/* --- decryption: the key lives only in this browser, never on the server --- */
let cryptoKey = null;

const hexToBytes = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));

// The service worker cannot read localStorage, so the E2E key (and only the key) is mirrored
// into a tiny IndexedDB store it can reach — that is what lets a push be decrypted on-device and
// shown with real content (未接来电 / 验证码) instead of a bare "点击查看".
function swKvPut(k, v){
  return new Promise((res) => {
    try {
      const r = indexedDB.open("sms-sw", 1);
      r.onupgradeneeded = () => r.result.createObjectStore("kv");
      r.onsuccess = () => { const t = r.result.transaction("kv", "readwrite"); t.objectStore("kv").put(v, k); t.oncomplete = () => res(); t.onerror = () => res(); };
      r.onerror = () => res();
    } catch { res(); }
  });
}

async function loadKey(){
  const hex = localStorage.getItem("sms_key") || "";
  swKvPut("sms_key", /^[0-9a-f]{64}$/i.test(hex) ? hex : "").catch(() => {});
  if (!/^[0-9a-f]{64}$/i.test(hex)) { cryptoKey = null; return; }
  cryptoKey = await crypto.subtle.importKey("raw", hexToBytes(hex), "AES-GCM", false, ["encrypt", "decrypt"]);
}

// Encrypt {to, body, sim} for the outbound queue in the same v1: format the phone decrypts.
// sim is "" (default), "0" (SIM 1) or "1" (SIM 2).
async function sealForSend(to, body, sim){
  if (!cryptoKey) throw new Error("未设置密钥");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify({ to, body, sim }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, pt));
  const buf = new Uint8Array(iv.length + ct.length); buf.set(iv); buf.set(ct, iv.length);
  return "v1:" + btoa(String.fromCharCode(...buf));
}

// Returns {sender, body, sim} or null when it cannot be read with the current key.
async function open_(msg){
  if (!msg.body.startsWith("v1:")) return { sender: msg.sender, body: msg.body, sim: "", dev: "" }; // pre-encryption
  if (!cryptoKey) return null;
  try {
    const raw = Uint8Array.from(atob(msg.body.slice(3)), (c) => c.charCodeAt(0));
    const pt  = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: raw.slice(0, 12) }, cryptoKey, raw.slice(12)
    );
    const o = JSON.parse(new TextDecoder().decode(pt));
    // k = receiving SIM label, d = which phone forwarded it; both are optional and both live
    // inside the ciphertext, so the server never learns either.
    return { sender: o.s, body: o.b, sim: o.k || "", dev: o.d || "" };
  } catch {
    return null;   // wrong key, or the ciphertext was tampered with — GCM catches both
  }
}

async function remove(id, li){
  const r = await fetch(location.origin + "/api/messages/" + id, { method: "DELETE" });
  if (r.status === 401) { location.href = "/login"; return; }
  if (!r.ok) return;
  li.style.transition = "opacity .2s,transform .2s";
  li.style.opacity = "0";
  li.style.transform = "translateX(12px)";
  setTimeout(() => {
    li.remove();
    if (!list.children.length) list.innerHTML = '<li class="empty">还没有短信</li>';
  }, 200);
}

async function render(rows, fresh){
  if (first) { list.innerHTML = ""; first = false; }
  // Drop the "还没有短信 / 加载中" placeholder whenever real rows are about to render. The first
  // clear above only fires once; the placeholder can be re-added later by poll() after the list is
  // emptied (e.g. every message deleted), and by then first is false — so without this a new SMS
  // rendered next to a stale "还没有短信".
  list.querySelector(".empty")?.remove();
  for (const msg of [...rows].reverse()) {   // server sends newest-first
    const plain = await open_(msg);
    if (plain) INBOX.set(msg.id, { id: msg.id, ts: msg.ts, number: norm(plain.sender), sender: plain.sender, body: plain.body, sim: plain.sim, dev: plain.dev });
    const li = document.createElement("li");
    if (fresh) li.className = "fresh";
    li.dataset.dev = plain?.dev || "";   // what the global device filter matches on

    const meta = document.createElement("div"); meta.className = "meta";
    const who = document.createElement("span"); who.className = "who";
    who.textContent = plain ? plain.sender : "🔒 已加密";
    const tm = document.createElement("span"); tm.className = "when"; tm.textContent = when(msg.ts);
    const del = document.createElement("button");
    del.className = "del"; del.textContent = "✕"; del.title = "删除";
    del.onclick = () => remove(msg.id, li);
    // 归属地 sits right after the number again: it was only exiled to a second line because the
    // SIM pill used to share this row, and that pill is now the bottom-right mark.
    const loc = document.createElement("span"); loc.className = "loc";
    if (plain) loc.dataset.num = plain.sender;   // filled by fillLocs once the table downloads
    meta.append(who, loc, tm);
    // Reply only makes sense for a real number, not an alphanumeric sender ID ("Google" etc).
    // NB: \\d (not \d) — this lives in the PAGE template literal, where \d would collapse to "d".
    if (plain && /\\d{3,}/.test(plain.sender)) {
      const reply = document.createElement("button");
      reply.className = "reply"; reply.textContent = "对话";
      reply.onclick = () => openThread(plain.sender);
      meta.append(reply);
    }
    meta.append(del);

    if (plain) {
      // One mark, "手机 · 卡", not a device chip plus a SIM chip: they answer the same question —
      // which phone, on which card. Either half may be missing (a message from before device ids,
      // or a missed call on a dual-SIM phone where the SIM genuinely cannot be known).
      const devName = plain.dev ? (DEVS.get(plain.dev)?.name || "设备 " + plain.dev.slice(0, 4)) : "";
      const via = [devName, plain.sim].filter(Boolean).join(" · ");
      if (via) {
        const t = document.createElement("span"); t.className = "via"; t.textContent = via;
        if (plain.dev) { t.dataset.dev = plain.dev; t.dataset.sim = plain.sim || ""; }
        li.append(t);
      }
    }

    const body = document.createElement("div");
    if (plain) {
      body.className = "body";
      renderBody(body, plain.body);
    } else {
      body.className = "locked";
      body.textContent = "无法解密 —— 点右上角「密钥」填入与手机相同的 SMS_KEY。";
    }
    li.append(meta);
    li.append(body);
    list.prepend(li);

    // Only when the tab is not on screen: alerting while the user is watching the row appear is
    // the redundant second notification. Foreground → the message simply shows up, no popup.
    if (fresh && document.hidden) notify(plain ? plain.sender : "新短信", plain ? plain.body : "（已加密）");
  }
  fillLocs();       // no-op until the table has arrived; loadPL() sweeps the backlog when it does
  applyDevFilter(); // newly added rows must respect the active device filter too
  fillVia();        // DEVS may still have been empty when these rows were built
}

// The device marks are written from DEVS, which renderBeat fills — and on a cold load the first
// render() runs before it, so every row came out labelled "设备 a1b2". Rewritten from the id kept
// on the element once the names are known.
function fillVia(){
  for (const el of document.querySelectorAll(".via[data-dev]")) {
    const d = DEVS.get(el.dataset.dev);
    if (!d) continue;
    const sim = el.dataset.sim || "";
    el.textContent = [d.name, sim].filter(Boolean).join(" · ");
    el.removeAttribute("data-dev");
  }
}

// Browser notification for each newly polled message. Only fires once permission is
// granted; the content is decrypted client-side, so it never came from the server in clear.
// In-page notification when the tab is open (desktop/Android). iOS only shows these from
// an installed PWA, so the real path there is Web Push via the service worker below.
function notify(title, text){
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  try {
    const n = new Notification(title, { body: text.slice(0, 120), tag: "sms-" + maxId });
    n.onclick = () => { window.focus(); n.close(); };
  } catch {}
}

const notifyBtn = document.getElementById("notifyBtn");
const standalone = () => window.navigator.standalone === true || matchMedia("(display-mode: standalone)").matches;
const pushOk = () => "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;

function paintNotifyBtn(){
  // The ✓ is a right-aligned span (see .mitem/.chk), not appended to the label, so toggle it.
  notifyBtn.querySelector(".chk").hidden = !("Notification" in window && Notification.permission === "granted");
}

function u8FromB64u(s){
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function enablePush(){
  const iOS = /iphone|ipad|ipod/i.test(navigator.userAgent);
  // On iOS, notifications only exist inside the home-screen PWA — not a normal tab.
  if (iOS && !standalone()) {
    alert("iPhone 开启步骤：用 Safari 打开本页 → 点底部分享按钮 → 添加到主屏幕；" +
          "然后从主屏幕上的「验证码」图标进入，再点这里的「通知」即可开启。");
    return;
  }
  if (!pushOk()) { alert("此浏览器不支持推送通知。"); return; }

  const perm = await Notification.requestPermission().catch(() => "denied");
  if (perm !== "granted") { paintNotifyBtn(); return; }

  try {
    const reg = await navigator.serviceWorker.register("/sw.js");
    await navigator.serviceWorker.ready;
    const key = (await (await fetch("/api/vapid")).text()).trim();
    // Always start from a FRESH endpoint. Reusing getSubscription() hands back a subscription
    // Apple may already have revoked, so "re-enable" silently re-saved the same dead one.
    const old = await reg.pushManager.getSubscription();
    if (old) {
      try { await fetch("/api/unsubscribe", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ endpoint: old.endpoint }) }); } catch {}
      try { await old.unsubscribe(); } catch {}
    }
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: u8FromB64u(key) });
    const r = await fetch("/api/subscribe", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(sub),
    });
    alert(r.ok ? "已开启推送通知。" : "订阅保存失败，请重试。");
  } catch (e) {
    alert("开启失败：" + (e && e.message ? e.message : e));
  }
  paintNotifyBtn();
}
notifyBtn.onclick = enablePush;
const testPushBtn = document.getElementById("testPushBtn");
testPushBtn.onclick = async () => {
  try {
    const r = await fetch("/api/testpush", { method: "POST" });
    if (!r.ok) { alert("测试推送失败（未登录？）"); return; }
    const j = await r.json().catch(() => ({}));
    if (!j.subs) { alert("当前没有推送订阅——请先在「通知」里开启并允许通知。"); return; }
    alert("已向 " + j.subs + " 个订阅发送测试推送。几秒内应收到通知；没收到就是订阅/设备端问题，把「通知」关掉再打开重订阅。");
  } catch { alert("测试推送出错，请重试。"); }
};
paintNotifyBtn();

/* --- phone liveness --- */
const beatEl = document.getElementById("beat");
// id -> {name, sims:[...]}, decrypted from /api/status. One merged "手机在线" line hid which
// phone was actually alive, so every device gets its own row now.
let DEVS = new Map();
let lastBeatSig = null;   // last-rendered device-strip signature; unchanged → skip the rebuild (no flicker)
let lastOutSig = null;    // same, for the outbox status strip

// Global device filter: null = show everything. Clicking a device row narrows the whole page to
// it — the message list and the default send target — which is the only way to answer "is THIS
// phone working" once more than one is reporting.
let ACTIVE_DEV = null;
try { ACTIVE_DEV = localStorage.getItem("activeDev") || null; } catch {}

function setActiveDev(id){
  ACTIVE_DEV = (ACTIVE_DEV === id) ? null : id;   // clicking the selected one clears the filter
  try {
    if (ACTIVE_DEV) localStorage.setItem("activeDev", ACTIVE_DEV);
    else localStorage.removeItem("activeDev");
  } catch {}
  renderBeat();
  applyDevFilter();
  fillVia();
}

// Messages carry their origin device in a data attribute, so filtering is a class toggle rather
// than a re-decrypt of the whole list.
function applyDevFilter(){
  let shown = 0, total = 0;
  for (const li of document.querySelectorAll("#list li")) {
    if (li.classList.contains("empty")) continue;
    total++;
    const d = li.dataset.dev || "";
    const vis = !ACTIVE_DEV || d === ACTIVE_DEV;
    li.style.display = vis ? "" : "none";
    if (vis) shown++;
  }
  // Otherwise a filter that matches nothing looks exactly like a broken page.
  document.querySelector("li.filternote")?.remove();
  if (ACTIVE_DEV && total && !shown) {
    const note = document.createElement("li");
    note.className = "empty filternote";
    note.textContent = "这台设备下没有消息（其余 " + total + " 条属于别的设备或更早的版本）";
    list.prepend(note);
  }
}

// The phone polls every 20s awake but only every 5 min asleep. 12 minutes turned out too tight:
// two real phones showed 10-11 minute gaps while still forwarding fine, so the dot flickered red
// on phones that were merely dozing. Four missed polls is a genuine outage; two is a nap. Actual
// freezing is reported separately and precisely by the gap counters, which is the better signal.
const ONLINE_MS = 20 * 60000;
const ago = (ms) => {
  const m = Math.floor(ms / 60000);
  if (m < 1) return "不到 1 分钟";
  if (m < 60) return m + " 分钟";
  const h = Math.floor(m / 60);
  return h < 24 ? h + " 小时" : Math.floor(h / 24) + " 天";
};

async function renderBeat(){
  let data;
  try { data = await (await fetch("/api/status", { cache: "no-store" })).json(); } catch { return; }
  const devs = data.devices || [];

  // Decrypt each device's {name, sims}; without the key we can still show liveness, just unnamed.
  const next = new Map();
  for (const d of devs) {
    let info = null;
    if (d.info && cryptoKey) { try { info = await openSend(d.info); } catch {} }
    next.set(d.id, {
      id: d.id, ts: d.ts, name: info?.n || ("设备 " + d.id.slice(0, 4)),
      sims: info?.s || [], caps: info?.c || null, gaps: info?.g || null, ver: info?.v || null, tr: info?.t || null, os: info?.os || null, ls: info?.ls || null,
    });
  }
  DEVS = next;

  // Skip the rebuild when nothing shown has changed. Polling every 10s was clearing and recreating
  // every card each time — that full repaint is the flicker. The signature covers only what is
  // displayed, so a bare heartbeat-ts tick is not a change; an offline card's elapsed label still
  // updates because its ago() bucket is part of the signature.
  const nowB = Date.now();
  const sig = JSON.stringify({
    act: ACTIVE_DEV,
    empty: devs.length ? 0 : (data.beat || 0),
    devs: [...next.values()].map((d) => {
      const on = nowB - d.ts < ONLINE_MS;
      return [d.id, on, d.name, d.caps, d.gaps, d.sims, d.ver, d.tr, d.os, d.ls, on ? 0 : ago(nowB - d.ts)];
    }),
  });
  if (sig === lastBeatSig) return;
  lastBeatSig = sig;

  beatEl.textContent = "";
  beatEl.className = "devstrip";
  if (!devs.length) {
    // Pre-device-id phones still stamp the old single heartbeat; show it rather than "no phones".
    const legacy = data.beat || 0;
    const line = document.createElement("div");
    line.style.cssText = "font-size:12.5px;font-weight:600;white-space:nowrap";
    if (!legacy) { line.textContent = "○ 还没有手机上报"; line.style.color = "var(--muted)"; }
    else if (Date.now() - legacy < ONLINE_MS) { line.textContent = "● 转发手机在线（旧版，未上报设备）"; line.style.color = "#22c55e"; }
    else { line.textContent = "● 转发手机可能离线（" + ago(Date.now() - legacy) + "前最后在线）"; line.style.color = "var(--danger)"; }
    beatEl.append(line);
    return;
  }
  // A filter you cannot clear is a trap: the 全部 chip used to appear only with two or more
  // phones, so after forgetting one (or reinstalling) a persisted ACTIVE_DEV silently hid every
  // untagged and undecryptable message with no way back. Offer it whenever a filter is active.
  if (ACTIVE_DEV && !DEVS.has(ACTIVE_DEV)) { ACTIVE_DEV = null; try { localStorage.removeItem("activeDev"); } catch {} }
  if (DEVS.size > 1 || ACTIVE_DEV) {
    const all = document.createElement("div");
    all.className = ACTIVE_DEV ? "dev-all" : "dev-all on";
    all.textContent = "全部";
    all.title = "显示所有设备的消息";
    all.onclick = () => { ACTIVE_DEV = null; try { localStorage.removeItem("activeDev"); } catch {} ; renderBeat(); applyDevFilter(); };
    beatEl.append(all);
  }
  for (const d of DEVS.values()) {
    const age = Date.now() - d.ts;
    const on = age < ONLINE_MS;
    // Liveness (the dot) and capability (can it still capture an SMS) are different questions: an
    // incoming SMS wakes even a frozen phone, so a dead poll does not mean lost messages. Show
    // them as two states. Any armed capture path — the notification listener, the default-SMS
    // role, or the RECEIVE_SMS broadcast — means it can still forward. null caps (old build or
    // undecryptable) → unknown, assert nothing.
    const canForward = d.caps
      ? (d.caps.notif === true || d.caps.sms === true || d.caps.recv === true) : null;
    // Two lines, not one: a phone name plus a carrier plus a status never fits a 375px row, and
    // the single-row version wrapped in the middle of a word.
    const box = document.createElement("div");
    box.className = ACTIVE_DEV === d.id ? "dev on" : "dev";
    box.title = ACTIVE_DEV === d.id ? "再点一次显示全部设备" : "只看这台设备";
    box.onclick = (e) => { if (!e.target.closest(".del")) setActiveDev(d.id); };
    const top = document.createElement("div"); top.className = "dev-top";
    const dot = document.createElement("span");
    dot.textContent = "●"; dot.style.color = on ? "#22c55e" : "var(--danger)";
    const name = document.createElement("span"); name.className = "dev-name";
    name.textContent = d.name;
    const state = document.createElement("span"); state.className = "dev-state";
    // Offline text goes calm (not red) when the phone can still forward — the red dot already
    // carries the liveness signal, and a red "离线" beside a working phone is the false alarm this
    // split exists to remove. Red is kept only when it genuinely cannot receive.
    state.style.color = on ? "#22c55e" : (canForward === false ? "var(--danger)" : "var(--muted)");
    state.textContent = on ? "在线" : ago(age) + "前离线";
    const forget = document.createElement("button");
    forget.className = "del"; forget.textContent = "✕"; forget.title = "移除这台设备";
    forget.onclick = async () => {
      if (!confirm("从列表中移除「" + d.name + "」？它再上报时会自动出现。")) return;
      await fetch("/api/device/forget", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: d.id }),
      });
      renderBeat();
    };
    top.append(dot, name, forget);
    const sub = document.createElement("div"); sub.className = "dev-sub";
    // The second state the user asked for, independent of the dot: can this phone still receive
    // and forward? Red when no capture path is armed (a real fault); green otherwise — and when it
    // is also offline, the green line is what says the red dot is only the poll asleep, not a phone
    // that stopped receiving.
    if (canForward === false) {
      const cap = document.createElement("div"); cap.className = "dev-warn";
      cap.textContent = "⚠ 收不到短信 · 检查通知访问/默认短信应用";
      sub.append(cap);
    } else if (canForward === true && !on) {
      // Online + working needs no line — the green dot already says it. The reassurance is only
      // worth showing when the phone is OFFLINE, so the red dot isn't misread as "stopped receiving".
      const cap = document.createElement("div"); cap.className = "dev-cap";
      cap.textContent = "● 仍可接收转发（离线只是轮询睡了）";
      sub.append(cap);
    }
    // The dot already says "online"; spelling it out again was noise. Offline still needs words,
    // because a red dot alone doesn't say whether it died a minute or a week ago.
    if (!on) sub.append(state);
    // A phone can be online and still half broken: notification access revoked kills missed-call
    // capture while SMS keeps arriving (that path is a broadcast), and losing the default-SMS role
    // kills sending. Both used to be invisible from the browser — you only found out by not
    // receiving something.
    const broken = [];
    if (d.caps) {
      if (d.caps.notif === false) broken.push("无通知权限·收不到未接来电");
      // "Can it send" is SEND_SMS, not the default-SMS role: an adb -g install sends without being
      // default (installer exemption). Only flag when SEND_SMS itself is missing.
      if (d.caps.send === false) broken.push("不能发短信·未授予发短信权限");
      // The measurement outranks the setting. ColorOS revokes this whitelist within minutes of it
      // being granted, so warning about it turns into a permanent red line on a phone that is
      // measurably fine — which trains the user to ignore the row where a real fault would show.
      // With suspensions actually recorded it is a diagnosis worth making; otherwise it is a
      // footnote, and lives on the muted line below.
      if (d.caps.batt === false && d.gaps && d.gaps[0] > 0) broken.push("未关电池优化·可能被杀");
    }
    // Being killed is not a setting you can read back, so the phone reports what actually
    // happened instead: how many times it went dark for longer than a poll interval.
    if (d.gaps && d.gaps[0] > 0) {
      broken.push("后台被挂起 " + d.gaps[0] + " 次（最长 " + d.gaps[1] + " 分钟）·发信会延迟");
    }
    if (broken.length) {
      const warn = document.createElement("div"); warn.className = "dev-warn";
      warn.textContent = "⚠ " + broken.join("；");
      warn.title = broken.join("；");
      sub.append(warn);
    }
    // The longest gap between two polls — shown ONLY when it is actually elevated (≥10 min). A
    // healthy phone sits at its 5-min interval, and printing that every time was noise; a genuinely
    // long gap still surfaces here, and real suspensions are flagged as a warning above anyway.
    if (d.gaps && d.gaps.length > 2 && d.gaps[2] >= 10) {
      const worst = document.createElement("div"); worst.className = "dev-sims";
      worst.textContent = "最长间隔 " + d.gaps[2] + " 分钟";
      sub.append(worst);
    }
    // Screen-off network: the piece the gap data can't show. A phone that wakes on schedule but
    // has no network (Huawei's 休眠断网) looks healthy above yet forwards nothing — this separates
    // "didn't wake" from "woke but no network". No-network wakes are a real fault (red); an
    // all-connected run is quiet positive evidence that the network is not the problem.
    // Only the problem case: screen-off wakes that found no network (Huawei's 熄屏断网). The
    // all-connected "始终有网" line was pure reassurance-noise on a healthy phone, so it's gone.
    if (d.gaps && d.gaps.length > 4 && d.gaps[4] > 0) {
      const net = document.createElement("div"); net.className = "dev-warn";
      net.textContent = "⚠ 熄屏唤醒 " + d.gaps[3] + " 次里 " + d.gaps[4] + " 次无网络·像是熄屏断网";
      sub.append(net);
    }
    // System version (Android + ColorOS/…): reported by the phone so the ROM is visible from here
    // — needed to tell a device what its exact keep-alive/permission settings paths are.
    if (d.os) {
      const o = document.createElement("div"); o.className = "dev-sims";
      o.textContent = String(d.os);
      sub.append(o);
    }
    // Last send outcome the phone reported — the REAL per-attempt reason (无服务/结果码/权限…),
    // visible even when the outbox row only shows the server's generic "多次尝试未送达".
    if (d.ls) {
      const fail = String(d.ls).startsWith("失败");
      const l = document.createElement("div");
      l.className = fail ? "dev-warn" : "dev-sims";
      l.textContent = "上次发送 " + d.ls;
      l.title = l.textContent;
      sub.append(l);
    }
    // One line per SIM rather than "a / b": on a dual-SIM phone joining them just pushed the
    // second card past the ellipsis, which is exactly the one you needed to see.
    for (const c of d.sims) {
      const line = document.createElement("div"); line.className = "dev-sims";
      line.textContent = String(c.name);
      sub.append(line);
    }
    // Footer row: the app version (left) and, watermarked bottom-right, the connection type the
    // phone last reported — "WIFI"/"4G"/"5G"/… . No emoji, muted; the label alone says whether it
    // is on Wi-Fi or burning the SIM's data. Legacy v1.5 phones send "cell" (no generation) → 蜂窝.
    if (d.ver || d.tr) {
      const net = d.tr === "cell" ? "蜂窝" : (d.tr || "");
      const line = document.createElement("div"); line.className = "dev-net";
      line.textContent = [net, d.ver ? "v" + d.ver : ""].filter(Boolean).join(" · ");
      sub.append(line);
    }
    box.append(top, sub);
    beatEl.append(box);
  }
  applyDevFilter();
  fillVia();   // rows painted before DEVS arrived still carry id-based placeholder labels
}

/* --- compose & send --- */
const outbox = document.getElementById("outbox");

// Decrypt an outbound payload to show what was sent. Mirrors open_ for the {to, body} shape.
async function openSend(payload){
  if (!payload.startsWith("v1:") || !cryptoKey) return null;
  try {
    const raw = Uint8Array.from(atob(payload.slice(3)), (c) => c.charCodeAt(0));
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12) }, cryptoKey, raw.slice(12));
    return JSON.parse(new TextDecoder().decode(pt));
  } catch { return null; }
}

async function renderOutbox(){
  let rows;
  try { const r = await fetch("/api/outbox/list", { cache: "no-store" }); if (!r.ok) return; rows = await r.json(); }
  catch { return; }
  // Decrypt all rows once, into the conversation store (used by the thread view).
  SENT = [];
  for (const r of rows) {
    const o = await openSend(r.payload);
    if (o) SENT.push({ id: r.id, ts: r.ts, number: norm(o.to), to: o.to, body: o.body, status: r.status, detail: r.detail });
  }
  if (threadDlg.open) renderThread();
  // Only show items still pending or recently finished — keep it a status strip, not a log.
  const show = rows.filter(r => r.status === "pending" || Date.now() - r.ts < 600000).slice(0, 8);
  // Same anti-flicker guard as the device strip: rebuild only when the shown rows actually change
  // (id set / status / detail), not on every 10s poll.
  const osig = JSON.stringify(show.map((r) => [r.id, r.status, r.detail]));
  if (osig === lastOutSig) return;
  lastOutSig = osig;
  outbox.innerHTML = "";
  for (const r of show) {
    const o = await openSend(r.payload);
    const div = document.createElement("div");
    const color = r.status === "sent" ? "#22c55e" : r.status === "failed" ? "var(--danger)" : "var(--muted)";
    const label = r.status === "sent" ? "已发送" : r.status === "failed" ? "失败" : "发送中…";
    div.style.cssText = "background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 12px;margin-bottom:8px;font-size:13px;display:flex;gap:10px";
    const left = document.createElement("span");
    left.style.cssText = "flex:1;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
    left.textContent = o ? "→ " + o.to + "：" + o.body : "→ （已加密）";
    const st = document.createElement("span");
    st.style.color = color; st.textContent = label + (r.detail ? " · " + r.detail : "");
    // Clear a row the user is done with — chiefly a failed/stuck send they don't want lingering.
    const del = document.createElement("button");
    del.textContent = "✕"; del.title = "删除";
    del.style.cssText = "border:0;background:none;color:var(--muted);cursor:pointer;font-size:14px;line-height:1;padding:0 2px;flex:none";
    del.onclick = async () => {
      del.disabled = true;
      try { await fetch("/api/outbox/" + r.id, { method: "DELETE" }); } catch {}
      renderOutbox();
    };
    div.append(left, st, del);
    outbox.append(div);
  }
}

const sendDlg = document.getElementById("sendDlg");
const sendSim = document.getElementById("sendSim");

// The phone's (encrypted) SIM report, cached after first decrypt.
// --- 号码归属地 ------------------------------------------------------------------------------
// A 253KB run-length table of all 517k number prefixes, fetched once and cached forever. The
// lookup runs here in the page, so a phone number is never sent to any server — the same rule
// the message bodies follow. Format is documented in the builder: "PL01", interned location
// records, then runs of (deltaStart, len, recIdx, carrier) varints.
let PLDB = null, AREA = null;
const CARD_NAME = { 1: "移动", 2: "联通", 3: "电信", 4: "电信虚拟", 5: "联通虚拟", 6: "移动虚拟", 7: "广电" };

function parsePL(bytes){
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]) !== "PL01") throw new Error("bad magic");
  let p = 4;
  const varint = () => { let v = 0, s = 1; for(;;){ const b = bytes[p++]; v += (b & 127) * s; if (!(b & 128)) break; s *= 128; } return v; };
  const recCount = dv.getUint16(p, true); p += 2;
  const dec = new TextDecoder();
  const records = new Array(recCount);
  for (let i = 0; i < recCount; i++){ const n = varint(); records[i] = dec.decode(bytes.subarray(p, p + n)); p += n; }
  const runCount = dv.getUint32(p, true); p += 4;
  const starts = new Int32Array(runCount), lens = new Int32Array(runCount),
        recs = new Int32Array(runCount), cards = new Uint8Array(runCount);
  let prev = 0;
  for (let i = 0; i < runCount; i++){ prev += varint(); starts[i] = prev; lens[i] = varint(); recs[i] = varint(); cards[i] = bytes[p++]; }
  return { records, starts, lens, recs, cards };
}

async function loadPL(){
  if (PLDB) return PLDB;
  try {
    const r = await fetch("/pl.bin", { cache: "force-cache" });
    if (!r.ok) return null;
    let bytes = new Uint8Array(await r.arrayBuffer());
    // Stored gzipped (253KB instead of 659KB) and served as opaque bytes, so unwrap it here.
    // Sniff the gzip magic rather than assuming, so a plain file would still parse.
    if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
      const ds = new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip")));
      bytes = new Uint8Array(await ds.arrayBuffer());
    }
    PLDB = parsePL(bytes);
    // 固话 comes free: every record already carries its 区号, so invert them into a lookup.
    AREA = new Map();
    for (const rec of PLDB.records){
      const f = rec.split("|");
      if (f[3] && !AREA.has(f[3])) AREA.set(f[3], f[1] || f[0]);
    }
  } catch { return null; }
  return PLDB;
}

// Last run starting at or before the prefix, then confirm the prefix is inside it — an
// unallocated prefix must not borrow its neighbour's location.
function plLookup(prefix){
  const s = PLDB.starts;
  let lo = 0, hi = s.length - 1, hit = -1;
  while (lo <= hi){ const mid = (lo + hi) >> 1; if (s[mid] <= prefix){ hit = mid; lo = mid + 1; } else hi = mid - 1; }
  if (hit < 0 || prefix >= s[hit] + PLDB.lens[hit]) return null;
  return { rec: PLDB.records[PLDB.recs[hit]], card: PLDB.cards[hit] };
}

// "江苏常州 · 移动" for a mobile, "上海" for a landline, "" for a service number like 10086.
function locOf(raw){
  if (!PLDB) return "";
  let d = String(raw || "").replace(/[^0-9]/g, "");
  if (d.length === 13 && d.slice(0, 2) === "86") d = d.slice(2);   // +86 prefixed
  if (d.length >= 11 && d[0] === "1"){
    const hit = plLookup(Number(d.slice(0, 7)));
    if (!hit) return "";
    const f = hit.rec.split("|");
    return (f[1] || f[0]) + " · " + (CARD_NAME[hit.card] || "");
  }
  if (d[0] === "0" && AREA) return AREA.get(d.slice(0, 4)) || AREA.get(d.slice(0, 3)) || "";
  return "";
}

// Rows render before the table has downloaded, so they carry the number and get filled in later.
function fillLocs(){
  if (!PLDB) return;
  for (const el of document.querySelectorAll(".loc[data-num]")){
    el.textContent = locOf(el.dataset.num);
    el.removeAttribute("data-num");
  }
}
loadPL().then(fillLocs);

// The SIM picker doubles as the device picker: each option value is "<deviceId>|<slot>", so
// choosing a card also decides which phone sends it. That is the whole point of device ids —
// before, a send went to whichever phone polled first, possibly over the wrong SIM entirely.
async function fillSim(sel){
  if (!DEVS.size) await renderBeat();   // populates DEVS
  sel.textContent = "";
  sel.append(new Option(DEVS.size > 1 ? "默认（任意手机的默认卡）" : "默认卡", ""));
  for (const d of DEVS.values()) {
    if (ACTIVE_DEV && d.id !== ACTIVE_DEV) continue;   // page is filtered to one phone
    if (d.sims.length) {
      for (const c of d.sims) {
        // Always name the phone, even with only one paired: the whole reason device ids exist is
        // being able to see which handset a send will go out from, and "SIM 1 · EE" alone doesn't
        // say that. Redundant-looking with one device, but that is the point.
        sel.append(new Option(d.name + " · " + c.name, d.id + "|" + c.slot));
      }
    } else {
      // A phone that hasn't reported its cards yet can still be targeted, on its default SIM.
      sel.append(new Option(d.name + " · 默认卡", d.id + "|"));
    }
  }
  // With the page pinned to one phone, "任意手机" is never what you want — preselect that phone.
  if (ACTIVE_DEV && sel.options.length > 1) sel.selectedIndex = 1;
}

// "<deviceId>|<slot>" -> {dev, sim} for postSend. Empty string means "no preference".
function pickOf(value){
  const v = String(value || "");
  if (!v) return { dev: null, sim: "" };
  const i = v.indexOf("|");
  return i < 0 ? { dev: null, sim: v } : { dev: v.slice(0, i) || null, sim: v.slice(i + 1) };
}

// Balance lookup by SMS. The phone reports each SIM's carrier in its name, so the right service
// number and command are picked automatically. Never match on a bare "mobile" — "T-Mobile" would
// be read as 中国移动. Commands vary by plan/region, so this only pre-fills: edit before sending.
// Commands are the ones each carrier documents itself, which are NOT uniform: Telecom uses a
// numeric scheme (102 余额 / 108 套餐), Mobile documents "YE" (the widely-quoted CXYE is only an
// unofficial alias), and Unicom is the one carrier where CXYE really is canonical. Provincial
// companies still差异, hence pre-fill rather than auto-send.
const CARRIERS = [
  { name: "中国电信", keys: ["电信", "china telecom", "chn-ct", "ctc"],      num: "10001", sms: "102",  data: "108"  },
  { name: "中国移动", keys: ["移动", "china mobile", "中国移动通信", "cmcc"], num: "10086", sms: "YE",   data: "CXLL" },
  { name: "中国联通", keys: ["联通", "china unicom", "unicom", "chn-cugsm"], num: "10010", sms: "CXYE", data: "CXLL" },
];
const matchesCarrier = (simName, c) => {
  const s = String(simName || "").toLowerCase();
  return c.keys.some(k => s.includes(k));
};
function carrierIndexOf(simName){ return CARRIERS.findIndex(c => matchesCarrier(simName, c)); }

// Pre-fills the compose dialog with the carrier's balance query — deliberately NOT one-click
// send: an SMS costs money and leaves the device, so you see it before it goes.
// Fills number + command from the chosen carrier. Always fills something: SIM detection is a
// convenience, never a precondition — the phone may not have reported its SIM names at all.
function applyCarrier(){
  const c = CARRIERS[Number(carrierSel.value) || 0];
  document.getElementById("sendTo").value = c.num;
  document.getElementById("sendBody").value = c.sms;
  document.getElementById("sendHint").textContent =
    "查余额：发 " + c.sms + " 到 " + c.num + "　｜　查流量：把内容改成 " + c.data;
  try { localStorage.setItem("carrier", carrierSel.value); } catch {}
}

async function openBalance(){
  if (!cryptoKey) { alert("请先点右上角「密钥」设置解密密钥，发信也用它加密。"); return; }
  await fillSim(sendSim);

  // Pick the carrier: the SIM's own name first, else whatever was used last, else the first.
  let idx = -1;
  for (const o of sendSim.options) {
    const i = carrierIndexOf(o.textContent);
    if (i >= 0) { idx = i; sendSim.value = o.value; break; }
  }
  if (idx < 0) {
    const saved = Number(localStorage.getItem("carrier"));
    idx = CARRIERS[saved] ? saved : 0;
  }

  carrierSel.textContent = "";
  CARRIERS.forEach((c, i) => carrierSel.append(new Option(c.name, String(i))));
  carrierSel.value = String(idx);
  applyCarrier();

  document.getElementById("sendTitle").textContent = "查话费";
  document.getElementById("carrierWrap").style.display = "";
  document.getElementById("sendHint").style.display = "";
  sendDlg.showModal();
}
carrierSel.onchange = applyCarrier;

// Encrypt + enqueue a send. Throws on failure; redirects on 401.
// pick is the SIM select's value: "<deviceId>|<slot>". The slot stays inside the ciphertext
// (the server must not learn which carrier), while the device id has to be plaintext — it is what
// the server matches against the polling phone to decide who may claim the row.
async function postSend(to, body, pick){
  const { dev, sim } = pickOf(pick);
  const payload = await sealForSend(to, body, sim);
  const r = await fetch("/api/send", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ payload, dev }),
  });
  if (r.status === 401) { location.href = "/login"; throw new Error("401"); }
  if (!r.ok) throw new Error(r.status);
}

// Header "发短信" — compose to any number.
function openCompose(to){
  if (!cryptoKey) { alert("请先点右上角「密钥」设置解密密钥，发信也用它加密。"); return; }
  document.getElementById("sendTo").value = to || "";
  document.getElementById("sendBody").value = "";
  document.getElementById("sendTitle").textContent = "发短信";
  // Both belong to the 话费 path only.
  document.getElementById("sendHint").style.display = "none";
  document.getElementById("carrierWrap").style.display = "none";
  fillSim(sendSim);
  sendDlg.showModal();
  (to ? document.getElementById("sendBody") : document.getElementById("sendTo")).focus();
}
document.getElementById("sendBtn").onclick = () => openCompose("");
document.getElementById("balBtn").onclick = openBalance;

/* --- 定时保号 (keep-alive schedule): a web switch + time; the server Cron Trigger queues the
   stored 保号 SMS when due. Off by default — nothing sends until you turn it on. --- */
const kaDlg = document.getElementById("kaDlg");
const kaOn  = document.getElementById("kaOn");
const kaSim = document.getElementById("kaSim");
const kaPad2 = (n) => String(n).padStart(2, "0");
const kaToLocalInput = (d) =>
  d.getFullYear() + "-" + kaPad2(d.getMonth()+1) + "-" + kaPad2(d.getDate()) + "T" + kaPad2(d.getHours()) + ":" + kaPad2(d.getMinutes());
function kaDefaultWhen(){ const d = new Date(); d.setDate(d.getDate() + 1); d.setHours(10, 0, 0, 0); return d; }
function kaCarrierIdx(){
  const opt = kaSim.options[kaSim.selectedIndex];
  return opt ? carrierIndexOf(opt.textContent) : -1;   // -1 = SIM name has no known carrier
}
function kaApplyHint(){
  const c = CARRIERS[kaCarrierIdx()];
  document.getElementById("kaHint").textContent = c
    ? "将定时发送：" + c.sms + " → " + c.num + "（查话费 · " + c.name + "）"
    : "⚠️ 没从这张 SIM 认出运营商，无法确定查费指令 —— 换一张能识别运营商的卡，或用「话费」手动发。";
}
function kaDim(){ document.getElementById("kaFields").style.opacity = kaOn.checked ? "1" : ".45"; }
kaSim.onchange = kaApplyHint;
kaOn.onchange = kaDim;

async function openKeepalive(){
  if (!cryptoKey) { alert("请先点右上角「密钥」设置解密密钥，保号短信也用它加密。"); return; }
  await fillSim(kaSim);
  let cfg = { enabled: false };
  try {
    const r = await fetch("/api/keepalive", { cache: "no-store" });
    if (r.status === 401) { location.href = "/login"; return; }
    if (r.ok) cfg = await r.json();
  } catch {}
  kaOn.checked = !!cfg.enabled;
  document.getElementById("kaEvery").value = cfg.interval || 30;
  document.getElementById("kaWhen").value = kaToLocalInput(cfg.next ? new Date(cfg.next) : kaDefaultWhen());
  // Preselect carrier from the SIM's own name, else last used, else the first.
  // Default to the first SIM whose name identifies a carrier.
  for (const o of kaSim.options) { if (carrierIndexOf(o.textContent) >= 0) { kaSim.value = o.value; break; } }
  kaApplyHint(); kaDim();
  kaDlg.showModal();
}
document.getElementById("kaBtn").onclick = openKeepalive;
document.getElementById("kaCancel").onclick = () => kaDlg.close();
document.getElementById("kaSave").onclick = async () => {
  const body = { enabled: kaOn.checked };
  if (body.enabled) {
    const whenVal = document.getElementById("kaWhen").value;
    const next = whenVal ? new Date(whenVal).getTime() : NaN;
    if (!Number.isFinite(next)) { alert("请设置下次发送时间。"); return; }
    const interval = Math.min(365, Math.max(1, parseInt(document.getElementById("kaEvery").value, 10) || 30));
    const c = CARRIERS[kaCarrierIdx()];
    if (!c) { alert("没从所选 SIM 认出运营商，无法确定查费指令。请换一张卡，或用「话费」手动发。"); return; }
    const { dev, sim } = pickOf(kaSim.value);
    body.payload = await sealForSend(c.num, c.sms, sim);
    body.dev = dev; body.next = next; body.interval = interval;
  }
  const r = await fetch("/api/keepalive", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (r.status === 401) { location.href = "/login"; return; }
  if (!r.ok) { alert("保存失败：" + r.status); return; }
  kaDlg.close();
  renderKaStatus();
  alert(body.enabled ? "已开启定时保号。" : "已关闭定时保号。");
};

// Compact "what's scheduled" chip under the heartbeat. Renders nothing when 保号 is off, so the
// strip only shows once a task is actually running. Carrier/command are decrypted client-side
// (server only ever held the ciphertext). Click to edit.
// Last 4 digits of the kept SIM's own number, from what the phone reported ("SIM 1 · 中国电信 ·
// 1234"). Often blank — modern Android hides the SIM's own number — then we just show the carrier.
// Device · SIM · carrier line for the corner watermark. Prefer what the phone reported (has the
// SIM slot + carrier, and the number's last 4 when Android exposes it); fall back to the carrier
// inferred from the service number.
async function kaSimTag(dev, slot, to){
  if (dev && slot !== "" && slot != null) {
    if (!DEVS.size) { try { await renderBeat(); } catch {} }
    const d = DEVS.get(dev);
    const sim = d && (d.sims || []).find(x => String(x.slot) === String(slot));
    if (d && sim) return d.name + " · " + sim.name;
  }
  const c = CARRIERS.find(x => x.num === to);
  return c ? c.name : "";
}
async function renderKaStatus(){
  const el = document.getElementById("kaStatus");
  el.textContent = "";
  let cfg;
  try { const r = await fetch("/api/keepalive", { cache: "no-store" }); if (!r.ok) return; cfg = await r.json(); }
  catch { return; }
  if (!cfg.enabled || !cfg.next) return;                 // off -> show nothing
  let cmd = "查话费", tag = "";
  if (cfg.payload && cryptoKey) {
    const m = await openSend(cfg.payload);               // {to, body, sim}
    if (m) { cmd = "发 " + m.body; tag = await kaSimTag(cfg.dev, m.sim, m.to); }
  }
  const d = new Date(cfg.next), p = (n) => String(n).padStart(2, "0");
  const when = (d.getMonth()+1) + "/" + d.getDate() + " " + p(d.getHours()) + ":" + p(d.getMinutes());
  const chip = document.createElement("div");
  chip.style.cssText = "display:flex;flex-direction:column;gap:3px;margin:8px 0 14px;padding:8px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);font-size:12.5px;color:var(--ink)";
  const top = document.createElement("div");
  top.style.cssText = "display:flex;align-items:center;gap:10px";
  const label = document.createElement("span");
  label.style.cssText = "flex:1;min-width:0;line-height:1.5;cursor:pointer";
  label.textContent = "🛡 " + cmd + " · 下次 " + when + " · 每 " + (cfg.interval || 30) + " 天";
  label.title = "点击修改定时保号";
  label.onclick = openKeepalive;
  const cancel = document.createElement("span");
  cancel.textContent = "取消";
  cancel.title = "取消定时保号";
  cancel.style.cssText = "flex:none;white-space:nowrap;padding:3px 10px;border:1px solid var(--line);border-radius:7px;color:var(--danger);cursor:pointer";
  cancel.onclick = async () => {
    if (!confirm("取消定时保号？之后不再自动发送。")) return;
    try { await fetch("/api/keepalive", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: false }) }); } catch {}
    renderKaStatus();                                    // chip disappears once disabled
  };
  top.append(label, cancel);
  chip.append(top);
  if (tag) {
    const wm = document.createElement("span");
    wm.textContent = tag;                                // faint bottom-right watermark: 设备·SIM·运营商
    wm.style.cssText = "align-self:flex-end;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:10px;color:var(--muted);opacity:.65";
    chip.append(wm);
  }
  el.append(chip);
}

// ⋯ sheet for the rare actions. Capture phase, so the sheet is already closed by the time the
// row's own handler opens its dialog — two modals open at once misbehaves.
const moreBtn = document.getElementById("moreBtn");
const closeMenu = () => { moreMenu.hidden = true; };
moreBtn.onclick = (e) => {
  e.stopPropagation();
  if (!moreMenu.hidden) { closeMenu(); return; }
  // Anchor under the ⋯ button, right-aligned to it (fixed, so the sticky header doesn't clip it).
  const r = moreBtn.getBoundingClientRect();
  moreMenu.style.top = (r.bottom + 6) + "px";
  moreMenu.style.right = Math.max(8, innerWidth - r.right) + "px";
  moreMenu.hidden = false;
};
// Picking an item runs its own handler (bound by id elsewhere) and then dismisses the menu.
moreMenu.addEventListener("click", (e) => { if (e.target.closest(".mitem")) closeMenu(); });
document.addEventListener("click", (e) => { if (!moreMenu.hidden && !e.target.closest("#moreMenu,#moreBtn")) closeMenu(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeMenu(); });
document.getElementById("sendCancel").onclick = () => sendDlg.close();
document.getElementById("sendGo").onclick = async () => {
  const to = document.getElementById("sendTo").value.trim();
  const body = document.getElementById("sendBody").value;
  const sim = document.getElementById("sendSim").value;
  if (!to || !body.trim()) { alert("号码和内容都要填。"); return; }
  try {
    await postSend(to, body, sim);
    sendDlg.close();
    alert("已排队，手机将在约 20 秒内发出。可下拉查看状态。");
  } catch (e) {
    if (e.message !== "401") alert("发送失败：" + (e && e.message ? e.message : e));
  }
};

/* --- conversation / chat view --- */
const threadDlg = document.getElementById("threadDlg");
const threadBody = document.getElementById("threadBody");
const threadText = document.getElementById("threadText");
const threadSim = document.getElementById("threadSim");
let threadNum = "", threadRaw = "";

async function openThread(rawNumber){
  if (!cryptoKey) { alert("请先点右上角「密钥」设置解密密钥。"); return; }
  threadRaw = rawNumber; threadNum = norm(rawNumber);
  // Same 归属地 annotation as the list — useful precisely here, where you're about to reply to
  // a number you may not recognise. Empty for service numbers, so it just reads as the number.
  const where = locOf(rawNumber);
  document.getElementById("threadName").textContent = where ? rawNumber + "　" + where : rawNumber;
  await fillSim(threadSim);
  renderThread();
  threadDlg.showModal();
  threadText.focus();
}

// Rebuild the bubble list from the client-side store, merged and time-sorted.
function renderThread(){
  const items = [];
  for (const m of INBOX.values()) if (m.number === threadNum) items.push({ dir: "in", ts: m.ts, body: m.body, sim: m.sim });
  for (const s of SENT) if (s.number === threadNum) items.push({ dir: "out", ts: s.ts, body: s.body, status: s.status, detail: s.detail });
  items.sort((a, b) => a.ts - b.ts);
  const nearBottom = threadBody.scrollHeight - threadBody.scrollTop - threadBody.clientHeight < 60;
  threadBody.textContent = "";
  if (!items.length) {
    const e = document.createElement("div"); e.className = "thread-empty"; e.textContent = "还没有对话记录";
    threadBody.append(e); return;
  }
  for (const it of items) {
    const b = document.createElement("div"); b.className = "bubble " + (it.dir === "in" ? "inb" : "out");
    const t = document.createElement("div"); t.textContent = it.body; b.append(t);
    const meta = document.createElement("div"); meta.className = "bmeta";
    let label = when(it.ts);
    if (it.dir === "in" && it.sim) label += " · " + it.sim;
    if (it.dir === "out") {
      label += " · " + (it.status === "sent" ? "已发送"
        : it.status === "failed" ? ("失败" + (it.detail ? " · " + it.detail : ""))
        : "发送中…");
    }
    meta.textContent = label; b.append(meta);
    threadBody.append(b);
  }
  if (nearBottom) threadBody.scrollTop = threadBody.scrollHeight;
}

document.getElementById("threadClose").onclick = () => threadDlg.close();
document.getElementById("threadSend").onclick = async () => {
  const body = threadText.value;
  if (!body.trim()) return;
  const btn = document.getElementById("threadSend"); btn.disabled = true;
  try {
    await postSend(threadRaw, body, threadSim.value);
    threadText.value = ""; threadText.style.height = "auto";
    await renderOutbox();   // pulls the new pending row into SENT, which re-renders the thread
  } catch (e) {
    if (e.message !== "401") alert("发送失败：" + (e && e.message ? e.message : e));
  } finally { btn.disabled = false; }
};
// Enter sends, Shift+Enter newlines; textarea grows with content.
threadText.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); document.getElementById("threadSend").click(); }
});
threadText.addEventListener("input", () => {
  threadText.style.height = "auto";
  threadText.style.height = Math.min(threadText.scrollHeight, 120) + "px";
});

let polling = false;
async function poll(){
  // The SW push-poke and the 10s interval can now fire poll() at once; two in flight both fetch
  // since the same maxId and would render the row twice. Serialise them — a poke dropped while a
  // poll runs is harmless, the running poll or the next interval covers it.
  if (polling) return;
  polling = true;
  try {
    const r = await fetch(location.origin + "/api/messages?since=" + maxId, { cache: "no-store" });
    if (r.status === 401) { location.href = "/login"; return; }
    if (!r.ok) throw new Error(r.status);
    const rows = await r.json();
    if (rows.length) {
      const fresh = maxId > 0;
      maxId = Math.max(maxId, ...rows.map(m => m.id));
      await render(rows, fresh);
      if (fresh && document.hidden) unread += rows.length;
    }
    // The placeholder counts as a child, so "no children" was never true on an empty inbox and
    // the page sat on 加载中 forever. The first flag stays true so a later render() still clears.
    if (!list.children.length || (first && list.querySelector(".empty"))) {
      list.innerHTML = '<li class="empty">还没有短信</li>';
    }
    await renderOutbox();
    await renderBeat();
    dot.classList.remove("bad");
  } catch {
    dot.classList.add("bad");
  } finally {
    polling = false;
  }
  document.title = unread ? "(" + unread + ") 短信" : "短信";
}

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    unread = 0; document.title = "短信";
    document.querySelectorAll("li.fresh").forEach(el => el.classList.remove("fresh"));
  }
});

/* --- key dialog --- */
const dlg = document.getElementById("keyDlg");
const keyInput = document.getElementById("keyInput");
document.getElementById("keyBtn").onclick = () => {
  keyInput.value = localStorage.getItem("sms_key") || "";
  dlg.showModal();
};
document.getElementById("keyCancel").onclick = () => dlg.close();
document.getElementById("keyClear").onclick = async () => {
  localStorage.removeItem("sms_key");
  await loadKey(); dlg.close(); reload();
};
document.getElementById("keySave").onclick = async () => {
  const v = keyInput.value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) { keyInput.style.borderColor = "var(--danger)"; return; }
  keyInput.style.borderColor = "";
  localStorage.setItem("sms_key", v);
  await loadKey(); dlg.close(); reload();
};

// Re-fetch from scratch so already-rendered ciphertext is replaced, not appended to.
function reload(){
  maxId = 0; first = true; list.innerHTML = '<li class="empty">加载中…</li>';
  poll();
  renderKaStatus();
}

// A push tells the SW an SMS landed; when the page is open the SW forwards it here so we refetch
// at once instead of waiting out the 10s interval — so the row appears the moment the push fires.
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.addEventListener("message", (e) => {
    if (e.data && e.data.type === "sms") poll();
  });
}

// Pull-to-refresh, for the installed PWA where there is no browser chrome to pull on. Touch only,
// and only when the page is already scrolled to the very top and no dialog is open — drag down past
// the threshold and release to force a poll (new messages + device status + outbox), the same
// refresh the 10s timer does, just on demand.
(function(){
  const el = document.createElement("div");
  el.id = "ptr";
  el.innerHTML = '<span class="sp"></span><span class="tx">↓ 下拉刷新</span>';
  document.body.appendChild(el);
  const tx = el.querySelector(".tx");
  const scroller = document.scrollingElement || document.documentElement;
  const TH = 56;                 // reveal px past which release triggers a refresh
  let y0 = 0, active = false, reveal = 0, busy = false;
  const blocked = () => busy || scroller.scrollTop > 0 || !!document.querySelector("dialog[open]");
  addEventListener("touchstart", (e) => {
    if (e.touches.length !== 1 || blocked()) { active = false; return; }
    y0 = e.touches[0].clientY; active = true; reveal = 0;
    el.style.transition = "none";
  }, { passive: true });
  addEventListener("touchmove", (e) => {
    if (!active) return;
    const dy = e.touches[0].clientY - y0;
    if (dy <= 0 || scroller.scrollTop > 0) { active = false; el.style.transition = ""; el.style.transform = ""; return; }
    reveal = Math.min(dy * 0.5, 90);           // resisted, so it feels like a pull
    el.style.transform = "translateY(" + (reveal - 46) + "px)";
    tx.textContent = reveal >= TH ? "松开刷新" : "↓ 下拉刷新";
    if (dy > 8) e.preventDefault();            // take over from the native overscroll bounce
  }, { passive: false });
  addEventListener("touchend", async () => {
    if (!active) return;
    active = false;
    el.style.transition = "";
    if (reveal < TH) { el.style.transform = ""; return; }
    busy = true; el.classList.add("load"); el.style.transform = "translateY(6px)";
    // Await the refresh, but keep the spinner up for at least a moment so a fast poll still reads
    // as a deliberate refresh rather than a flicker.
    try { await Promise.all([poll(), new Promise((r) => setTimeout(r, 500))]); } catch {}
    el.classList.remove("load"); el.style.transform = ""; busy = false;
  }, { passive: true });
})();

(async () => {
  await loadKey();
  await poll();
  renderKaStatus();
  setInterval(poll, 10000);
})();
</script>
</body></html>`;
