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

/* -------------------------------------------------------------- device auth */

async function sha256hex(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Who is this device? Two credentials coexist on the same routes:
//   - the phones' shared SEND_TOKEN → { dev, legacy: true }. dev may be empty (an old build that
//     never sent ?dev=), exactly as before — nothing about the phone path changes here.
//   - a module's own secret → { dev, status }. Modules are looked up by ?dev= and verified as
//     sha256(bearer) against devices.auth, so a D1 dump never contains a credential that works.
//   - anything else → null. Callers answer with whatever they answered before (403 / 401), so a
//     phone with a wrong token sees byte-for-byte what it always saw.
// The hash is compared with safeEqual like the token itself: not because a hash comparison leaks
// much, but because one code path for both means one thing to get right.
async function deviceAuth(request, env, url) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  const bearer = auth.slice(7);
  const dev = (url.searchParams.get("dev") || "").slice(0, 64);
  if (env.SEND_TOKEN && safeEqual(bearer, env.SEND_TOKEN)) return { dev, legacy: true };
  if (!dev || !bearer) return null;
  // The two columns arrive with setup.sh's ALTERs. If the code got deployed a step ahead of the
  // migration, a module simply cannot authenticate yet — and a phone with a wrong token must see
  // the 403/401 it always saw, not a 500 about a missing column.
  let row;
  try {
    row = await env.DB.prepare("SELECT auth, status, ts FROM devices WHERE id = ?").bind(dev).first();
  } catch { return null; }
  if (!row || !row.auth) return null;
  if (!safeEqual(await sha256hex(bearer), row.auth)) return null;
  return { dev, status: row.status, ts: Number(row.ts) || 0 };
}

// A device that authenticated but may not act: a module the web has not trusted yet (or has
// blocked). Phones are never gated — the legacy token predates the status column.
const deviceAllowed = (a) => !!a && (a.legacy || a.status === "trusted");

// How often an untrusted module's heartbeat is written. Its credential is self-issued, so anyone
// holding a pending row could otherwise turn a request loop into a billable D1 write loop.
const UNTRUSTED_BEAT_MS = 60_000;

// The poll batch shared by the phones' /api/outbox and the modules' /api/poll. Four statements,
// in this order, run atomically:
//  1. stamp last-seen (the web reads it to know the device is alive; no dev → the pre-device-id
//     single heartbeat, which the page still shows for old builds);
//  2. fail out rows claimed MAX_CLAIMS times that never came back acked — the device plainly
//     can't submit them (weak signal / lost acks) and they must not cycle forever;
//  3. give back claims stuck past the timeout so the next poll retries them. The window is
//     generous — a real send waits up to 60s for its delivery result — so a live device is never
//     second-guessed;
//  4. claim-on-read: flip pending → sending and RETURN those rows, so a lost ack after a real
//     send can't get the SMS sent twice. A row addressed to a device is only ever claimed by that
//     device; dev IS NULL means "any", which a single-phone setup keeps producing.
// Returns the statements so a caller can append its own to the same batch.
function pollStatements(env, dev, now) {
  const stamp = dev
    ? env.DB.prepare("INSERT INTO devices (id, ts) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET ts=excluded.ts").bind(dev, now)
    : env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('beat', ?)").bind(String(now));
  const failout = env.DB.prepare(
    "UPDATE outbox SET status='failed', detail='多次尝试未送达（弱信号或网络问题）' " +
    "WHERE status='sending' AND ts <= ? AND claims >= ?"
  ).bind(now - CLAIM_TIMEOUT_MS, MAX_CLAIMS);
  const stale = env.DB.prepare(
    "UPDATE outbox SET status='pending' WHERE status='sending' AND ts <= ? AND claims < ?"
  ).bind(now - CLAIM_TIMEOUT_MS, MAX_CLAIMS);
  const claim = env.DB.prepare(
    "UPDATE outbox SET status='sending', claims=claims+1 WHERE status='pending' AND (dev IS NULL OR dev = ?) RETURNING id, payload"
  ).bind(dev);
  return [stamp, failout, stale, claim];
}

const OTA_NAMES = new Set(["gw", "gcm"]);
const CMD_TYPES = new Set(["reboot", "ota", "bases"]);
const DEV_STATUSES = new Set(["pending", "trusted", "blocked"]);

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

  // Phones (SEND_TOKEN) or a trusted module (its own secret). A module the web has not trusted
  // gets the same 403 as a bad token: the device keeps the message queued and retries later.
  const u = new URL(request.url);
  if (!deviceAllowed(await deviceAuth(request, env, u))) {
    return new Response("forbidden", { status: 403 });
  }

  const body = await request.text();
  if (!body) return new Response("empty body", { status: 400 });

  // A backfill (the app re-forwarding the phone's existing inbox) arrives with quiet=1 and the
  // message's ORIGINAL time: stored like any other row, but no push — 50 old messages must not
  // become 50 notifications — and timestamped when it really arrived, not when it was re-sent.
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
      const a = await deviceAuth(request, env, url);
      if (!deviceAllowed(a)) return new Response("forbidden", { status: 403 });
      // ?dev= identifies which phone is polling. Everything is keyed on it now, because with two
      // phones sharing one token a single heartbeat hid which one had died, and a send meant for
      // one could be claimed and sent by the other, off the wrong SIM.
      const [, , , claim] = await env.DB.batch(pollStatements(env, a.dev, Date.now()));
      return Response.json(claim.results || []);
    }
    // Phone reports its name + SIM list, encrypted: both are PII, so the server keeps it opaque
    // and only the browser can read it. Per device, so two phones stop overwriting each other.
    if (request.method === "POST" && path === "/api/devinfo") {
      const a = await deviceAuth(request, env, url);
      if (!deviceAllowed(a)) return new Response("forbidden", { status: 403 });
      const dev = a.dev;
      if (!dev) return new Response('{"error":"bad"}', { status: 400 });
      const info = (await request.text()).slice(0, 4096);
      await env.DB.prepare(
        "INSERT INTO devices (id, ts, info) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET info=excluded.info"
      ).bind(dev, Date.now(), info).run();
      return Response.json({ ok: true });
    }
    // Web polls this for the per-device liveness list. `module` (has its own secret) is what lets
    // the page offer 信任/拉黑 and commands only where they mean something — on a phone, status
    // is ignored by the token path and a command would never be picked up.
    if (isRead && path === "/api/status") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      let results;
      try {
        ({ results } = await env.DB.prepare(
          "SELECT id, ts, info, status, (auth IS NOT NULL) AS module FROM devices ORDER BY ts DESC"
        ).all());
      } catch {
        // Code deployed ahead of setup.sh's ALTERs: the phones' strip must not go blank for that.
        ({ results } = await env.DB.prepare("SELECT id, ts, info FROM devices ORDER BY ts DESC").all());
      }
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
      const a = await deviceAuth(request, env, url);
      if (!deviceAllowed(a)) return new Response("forbidden", { status: 403 });
      const b = await request.json().catch(() => null);
      const id = Number(b?.id);
      if (!Number.isInteger(id)) return new Response('{"error":"bad"}', { status: 400 });
      const st = b.ok ? "sent" : "failed", detail = (b.detail || "").slice(0, 200);
      // Phones share one token and are all the owner's, so their ack has never been scoped and
      // stays that way. A module has an identity of its own: it may only close rows it could
      // have claimed — its own or the unaddressed ones — never another device's.
      const upd = a.legacy
        ? env.DB.prepare("UPDATE outbox SET status=?, detail=? WHERE id=?").bind(st, detail, id)
        : env.DB.prepare("UPDATE outbox SET status=?, detail=? WHERE id=? AND (dev IS NULL OR dev = ?)").bind(st, detail, id, a.dev);
      await upd.run();
      return Response.json({ ok: true });
    }

    // --- self-registering modules (Air780EHV) ------------------------------------------
    // A module has no operator to type a token into it. At first boot it makes its own secret,
    // registers here with everything it knows about itself (encrypted, like devinfo), and shows
    // up on the web as 待信任. Until someone clicks 信任 it can neither publish nor claim sends;
    // it just keeps re-registering and polling, so the answer to "is it trusted yet" is always
    // one poll away. No TOFU, no shared token: the phone's SEND_TOKEN is never on a module.
    if (request.method === "POST" && path === "/api/register") {
      const auth = request.headers.get("Authorization") || "";
      if (!auth.startsWith("Bearer ") || auth.length <= 7) return new Response("forbidden", { status: 403 });
      const dev = url.searchParams.get("dev") || "";
      if (!/^[0-9a-f]{16,64}$/.test(dev)) return new Response('{"error":"bad"}', { status: 400 });
      // The secret is the module's only credential for everything it will ever do here, so a weak
      // one (a buggy or copycat firmware registering with "a") must not become permanent. Part B
      // mints 32 hex from the TRNG; anything else is a client bug, not an auth failure.
      if (!/^[0-9a-f]{32,128}$/i.test(auth.slice(7))) return new Response('{"error":"bad"}', { status: 400 });
      // The blob is a few hundred bytes of ciphertext and a truncated one decrypts to nothing, so
      // an oversized body is refused — before it is read, like every other refusal below: nothing
      // here buffers a body for a request that is about to be turned away.
      if (Number(request.headers.get("Content-Length") || 0) > 4096) return new Response('{"error":"too large"}', { status: 413 });
      const h = await sha256hex(auth.slice(7));
      const now = Date.now();
      const readInfo = async () => (await request.text()).slice(0, 4096) || null;
      const row = await env.DB.prepare("SELECT auth, status, ts FROM devices WHERE id = ?").bind(dev).first();
      if (!row) {
        // Anyone who knows the URL can register (that is the point — nothing to configure), so
        // cap the unreviewed pile: past this a stranger's spam just gets 429 until the web tidies.
        const c = await env.DB.prepare("SELECT count(*) AS n FROM devices WHERE status='pending'").first();
        if ((c?.n || 0) >= 20) return new Response("too many pending devices", { status: 429 });
        await env.DB.prepare("INSERT INTO devices (id, ts, info, auth, status) VALUES (?, ?, ?, ?, 'pending')")
          .bind(dev, now, await readInfo(), h).run();
        return Response.json({ status: "pending" });
      }
      // A phone's id (no secret) can't be taken over by a module claiming the same id.
      if (!row.auth) return new Response('{"error":"conflict"}', { status: 409 });
      if (!safeEqual(h, row.auth)) return new Response("forbidden", { status: 403 });
      // Re-registration (every boot and every 30 min): refresh the self-description, and count it
      // as a heartbeat. Status is the web's to set, never the device's. A blocked module gets its
      // answer and nothing else; a pending one is written at most once a minute — both hold a
      // credential nobody has vetted, and neither may drive D1 writes at will.
      if (row.status === "blocked") return Response.json({ status: "blocked" });
      if (row.status === "trusted" || now - (Number(row.ts) || 0) >= UNTRUSTED_BEAT_MS) {
        await env.DB.prepare("UPDATE devices SET info=?, ts=? WHERE id=?").bind(await readInfo(), now, dev).run();
      }
      return Response.json({ status: row.status });
    }
    // The module's poll: /api/outbox plus the command channel, in one round trip. GET only —
    // a HEAD would claim rows and drop them. The legacy token is refused on purpose: phones
    // have /api/outbox, and a token that is on every phone must not be able to pick up commands
    // meant for a specific module.
    if (request.method === "GET" && path === "/api/poll") {
      const a = await deviceAuth(request, env, url);
      if (!a || a.legacy) return new Response("forbidden", { status: 403 });
      const now = Date.now();
      if (a.status !== "trusted") {
        // Still a heartbeat — the web shows "last seen" on a pending card so you can tell the
        // module you just powered on from one that registered last week — but no claim, no cmd,
        // at most one write a minute (the credential is self-issued), and none once blocked.
        if (a.status === "pending" && now - a.ts >= UNTRUSTED_BEAT_MS) {
          await env.DB.prepare("UPDATE devices SET ts=? WHERE id=?").bind(now, a.dev).run();
        }
        return Response.json({ status: a.status });
      }
      const cmdSel = env.DB.prepare(
        "SELECT id, payload FROM cmds WHERE dev=? AND status='pending' ORDER BY id LIMIT 1"
      ).bind(a.dev);
      const [, , , claim, cmds] = await env.DB.batch([...pollStatements(env, a.dev, now), cmdSel]);
      let cmd = null;
      const c = cmds.results?.[0];
      if (c) { try { cmd = Object.assign({ id: c.id }, JSON.parse(c.payload)); } catch {} }
      return Response.json({ status: "trusted", rows: claim.results || [], cmd });
    }
    // Module reports how a command went. Scoped to its own dev so one module can't close
    // another's command.
    if (request.method === "POST" && path === "/api/cmd/ack") {
      const a = await deviceAuth(request, env, url);
      if (!a || a.legacy || a.status !== "trusted") return new Response("forbidden", { status: 403 });
      const b = await request.json().catch(() => null);
      const id = Number(b?.id);
      if (!Number.isInteger(id)) return new Response('{"error":"bad"}', { status: 400 });
      await env.DB.prepare("UPDATE cmds SET status=?, detail=? WHERE id=? AND dev=?")
        .bind(b.ok ? "done" : "failed", String(b.detail || "").slice(0, 200), id, a.dev).run();
      return Response.json({ ok: true });
    }
    // The script an OTA command points at. Plain bytes, no signature here: the module checks
    // HMAC-SHA256 under SMS_KEY against cmd.hmac, which the browser computed — the server never
    // had the key and so can never hand a module code the owner did not sign.
    if (request.method === "GET" && path === "/api/ota/get") {
      const a = await deviceAuth(request, env, url);
      if (!a || a.legacy || a.status !== "trusted") return new Response("forbidden", { status: 403 });
      const name = url.searchParams.get("name") || "";
      if (!OTA_NAMES.has(name)) return new Response('{"error":"bad"}', { status: 400 });
      const bytes = await env.APK?.get("ota:" + name, "arrayBuffer");
      if (!bytes) return new Response("not found", { status: 404 });
      return new Response(bytes, {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Content-Length": String(bytes.byteLength),
          "Cache-Control": "no-cache",
        },
      });
    }

    // --- web side of the module registry (cookie session) -------------------------------
    if (request.method === "POST" && path === "/api/device/trust") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const b = await request.json().catch(() => null);
      if (!b?.id || !DEV_STATUSES.has(b.status)) return new Response('{"error":"bad"}', { status: 400 });
      await env.DB.prepare("UPDATE devices SET status=? WHERE id=?").bind(b.status, String(b.id).slice(0, 64)).run();
      return Response.json({ ok: true });
    }
    // Queue a command for a module. One pending per device: a module runs a command and reboots,
    // so a second one queued behind it would run against a state nobody looked at.
    if (request.method === "POST" && path === "/api/cmd") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const b = await request.json().catch(() => null);
      const dev = typeof b?.dev === "string" ? b.dev.slice(0, 64) : "";
      if (!dev || !CMD_TYPES.has(b.type)) return new Response('{"error":"bad"}', { status: 400 });
      const payload = { type: b.type };
      if (b.type === "ota") {
        if (!OTA_NAMES.has(b.name) || !/^[0-9a-f]{64}$/i.test(String(b.hmac || ""))) {
          return new Response('{"error":"bad"}', { status: 400 });
        }
        payload.name = b.name; payload.hmac = String(b.hmac).toLowerCase();
      } else if (b.type === "bases") {
        // The module will only ever talk to these, so a typo here bricks it until an SMS command
        // (if OWNER is set) or a reflash — validate hard. The normalised list is what gets stored.
        // The module appends "/api/…" to each entry, so nothing that would swallow that — a query,
        // a fragment, quotes, escapes — may ride along, and a trailing "/" is dropped so the join
        // is well-formed. The page's 改域名 prompt applies the same rule before asking.
        //
        // Signed like "ota", and for a stronger reason: `bases` moves the module to another
        // server for good, so an unsigned one lets an on-path attacker (TLS verification is off
        // by default) or a compromised Worker capture it permanently — block/forget would never
        // reach it again. The browser MACs "bases\n" + the normalised value under SMS_KEY, which
        // this server never holds: it can neither verify the signature nor forge one. It only
        // insists one is present and carries it to the module, which checks it against the value
        // exactly as stored. The normalisation below is the same rule the page already applied,
        // so on a page-sent value it is a no-op and what is stored is what was signed.
        if (!/^[0-9a-f]{64}$/i.test(String(b.hmac || ""))) {
          return new Response('{"error":"bad"}', { status: 400 });
        }
        const list = String(b.value || "").split(",").map((s) => s.trim().replace(/\/+$/, "")).filter(Boolean);
        const okUrl = (s) => s.length <= 120 && /^https:\/\/[A-Za-z0-9.-]+(:[0-9]+)?(\/[A-Za-z0-9._~\/-]*)?$/.test(s);
        if (!list.length || list.length > 5 || !list.every(okUrl)) {
          return new Response('{"error":"bad"}', { status: 400 });
        }
        payload.value = list.join(",");
        payload.hmac = String(b.hmac).toLowerCase();
      }
      // Only a module can pick a command up; refusing for phones keeps a stray click from parking
      // a row that would show "待执行" forever.
      const row = await env.DB.prepare("SELECT auth FROM devices WHERE id = ?").bind(dev).first();
      if (!row?.auth) return new Response('{"error":"nodev"}', { status: 404 });
      const pend = await env.DB.prepare("SELECT id FROM cmds WHERE dev=? AND status='pending' LIMIT 1").bind(dev).first();
      if (pend) return new Response('{"error":"pending"}', { status: 409, headers: { "Content-Type": "application/json" } });
      const r = await env.DB.prepare("INSERT INTO cmds (ts, dev, payload) VALUES (?, ?, ?)")
        .bind(Date.now(), dev, JSON.stringify(payload)).run();
      return Response.json({ ok: true, id: r.meta?.last_row_id });
    }
    if (isRead && path === "/api/cmd/list") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const dev = (url.searchParams.get("dev") || "").slice(0, 64);
      const { results } = await env.DB.prepare(
        "SELECT id, ts, payload, status, detail FROM cmds WHERE dev=? ORDER BY id DESC LIMIT 20"
      ).bind(dev).all();
      return Response.json(results || []);
    }
    // Withdraw a command the module has not picked up yet. A done/failed row is history and stays.
    if (request.method === "DELETE" && path.startsWith("/api/cmd/")) {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const id = Number(path.slice("/api/cmd/".length));   // an integer: nothing to decode, and "%" must not throw
      if (!Number.isInteger(id)) return new Response('{"error":"bad"}', { status: 400 });
      const r = await env.DB.prepare("DELETE FROM cmds WHERE id=? AND status='pending'").bind(id).run();
      return Response.json({ ok: true, deleted: r.meta?.changes || 0 });
    }
    // Stage a script for OTA. Stored as-is in KV; the signature travels in the cmd, not here,
    // because it is made in the browser with the key the server never holds. The Lua sniff is
    // only there to catch uploading the wrong file (a .soc, a zip) — it is not a security check.
    if (request.method === "POST" && path === "/api/ota/put") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      const name = url.searchParams.get("name") || "";
      if (!OTA_NAMES.has(name)) return new Response('{"error":"bad"}', { status: 400 });
      // The file's own HMAC, computed in the browser under SMS_KEY — the same value the "ota"
      // command carries. Optional, and never trusted here (the server has no key to check it
      // with): it is kept beside the file only so the 短信指令 composer can offer "用上次上传的"
      // without the file in hand, because an SMS "#ota gw <hmac>" is nothing but that hmac. A
      // malformed one is refused rather than stored — a stored lie would be copied straight into
      // a command the module then rejects, with nothing on screen to say why.
      const hmacQ = url.searchParams.get("hmac");
      if (hmacQ !== null && !/^[0-9a-f]{64}$/i.test(hmacQ)) return new Response('{"error":"bad hmac"}', { status: 400 });
      if (Number(request.headers.get("Content-Length") || 0) > 200_000) return new Response('{"error":"too large"}', { status: 413 });
      const bytes = await request.arrayBuffer();
      if (bytes.byteLength > 200_000) return new Response('{"error":"too large"}', { status: 413 });
      const text = new TextDecoder().decode(bytes);
      const looksLua = text.includes("return M") || /^\s*(--|local\b)/.test(text);
      if (!bytes.byteLength || !looksLua) return new Response('{"error":"not lua"}', { status: 400 });
      const sha256 = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
        .map((b) => b.toString(16).padStart(2, "0")).join("");
      const meta = { size: bytes.byteLength, ts: Date.now(), sha256 };
      if (hmacQ) meta.hmac = hmacQ.toLowerCase();
      await env.APK.put("ota:" + name, bytes);
      await env.APK.put("ota:" + name + ":meta", JSON.stringify(meta));
      return Response.json({ ok: true, size: meta.size, sha256 });
    }
    if (isRead && path === "/api/ota/meta") {
      if (!(await sessionValid(request, env))) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      // The stored meta verbatim — size/ts/sha256, plus `hmac` when the upload carried one.
      // An entry written before that param existed simply has no `hmac`, and the page's
      // 「用上次上传的」shortcut stays hidden for it.
      const out = {};
      for (const n of OTA_NAMES) {
        const m = await env.APK?.get("ota:" + n + ":meta");
        out[n] = m ? JSON.parse(m) : null;
      }
      return Response.json(out);
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
      const a = await deviceAuth(request, env, url);
      if (!a) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      if (!deviceAllowed(a)) return new Response("forbidden", { status: 403 });
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
      const a = await deviceAuth(request, env, url);
      if (!a) {
        return new Response('{"error":"unauthorized"}', { status: 401, headers: { "Content-Type": "application/json" } });
      }
      if (!deviceAllowed(a)) return new Response("forbidden", { status: 403 });
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
      // The deploy timestamp is a binding, not a constant, so the page shows when the Worker
      // actually shipped rather than whatever someone last remembered to edit.
      const res = path === "/"
        ? html(PAGE.replace("__BUILT__", env.CF_VERSION_METADATA?.timestamp || ""))
        : await handleList(request, env);
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
    // a phone that goes offline mid-send leaves its row "发送中" forever.
    //
    // outbox.ts is the INSERT time and the claim never touches it, so this grace period is really
    // "time since the row was written", not "time since it was claimed". At a 30 s poll that was
    // the same thing to within half a minute; on the module's slow tier a row written at 22:05 is
    // not claimed until 22:15, and a lost ack would then see this cron mark it 失败 somewhere
    // between 20 and 35 minutes — overruling the two retries that failout/stale (MAX_CLAIMS) are
    // there to give it, and putting "发送未完成" on screen for an SMS that actually went out.
    // The claims guard puts this back to what the comment always claimed: only rows that already
    // burned their retry budget.
    await env.DB.prepare(
      "UPDATE outbox SET status='failed', detail='发送未完成（手机离线/被杀），已超时' " +
      "WHERE status='sending' AND ts <= ? AND claims >= ?"
    ).bind(Date.now() - 20 * 60_000, MAX_CLAIMS).run();
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
.top .who{display:flex;flex-direction:column;gap:2px;min-width:0}
.top .ver{font-size:11px;line-height:1;color:var(--muted);white-space:nowrap}
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
/* A module's IMEI/ICCID and 脚本/固件/ota lines: these are exactly what you read to tell two
   boards apart and to decide what to push, so they wrap rather than ellipsise. */
.dev-id{font-size:11.5px;color:var(--muted);margin-top:2px;padding-left:15px;white-space:normal;line-height:1.4;overflow-wrap:anywhere}
/* Self-registered modules. A pending card is the one thing on the strip that wants a click, so it
   gets the amber ring the rest of the page never uses; blocked is deliberately dull. */
.dev.pend{border-color:#f59e0b;box-shadow:0 0 0 2px rgba(245,158,11,.28)}
.dev.pend.on{box-shadow:0 0 0 2px var(--ring),0 0 0 4px rgba(245,158,11,.28)}
.dev.blk{opacity:.7}
.dev-badge{flex:none;font-size:10px;font-weight:700;padding:1px 6px;border-radius:5px;white-space:nowrap;line-height:1.5}
.dev-badge.pend{color:#b45309;background:rgba(245,158,11,.2)}
.dev-badge.blk{color:var(--muted);background:color-mix(in srgb,var(--muted) 16%,transparent)}
/* Trust + command buttons live on their own row at the bottom of the card, small enough that a
   card with three of them is still narrower than a phone screen. */
.dev-acts{display:flex;flex-wrap:wrap;gap:4px;margin-top:6px}
.dev-acts button{font-size:11px;padding:2px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);cursor:pointer;line-height:1.6;white-space:nowrap}
.dev-acts button:hover{border-color:var(--muted)}
.dev-acts button.ok{color:#16a34a;border-color:color-mix(in srgb,#22c55e 45%,transparent);font-weight:600}
.dev-acts button.bad{color:var(--danger)}
.dev-acts button:disabled{opacity:.5;cursor:default}
/* Last command and its outcome — the module's own words (bytes written, why the HMAC failed). */
.dev-cmd{font-size:11px;color:var(--muted);margin-top:3px;white-space:normal;line-height:1.35;overflow-wrap:anywhere}
.dev-cmd.fail{color:var(--danger)}
.dev-cmd .undo{color:var(--accent);cursor:pointer;margin-left:4px;font-weight:600}
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
/* 短信指令 composer. The field vocabulary is the one the 发短信/定时保号 dialogs already use,
   lifted out of their inline styles because this dialog has six of them. */
.fl{display:block;font-size:13px;color:var(--muted);margin:-4px 0 6px}
.fs{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font-size:16px;margin-bottom:14px}
.fh{color:var(--muted);font-size:12.5px;line-height:1.55;margin:10px 0 0}
/* The line to send: selectable and wrapping, because the fallback when the QR won't scan is
   reading or copying it by hand. */
.smsline{
  font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--bg);
  border:1px solid var(--line);border-radius:9px;padding:10px 12px;overflow-wrap:anywhere;
  user-select:all;-webkit-user-select:all;
}
/* White ground regardless of the page theme: a scanner reading a dark-on-dark QR sees nothing,
   and the quiet zone is part of the SVG so no padding may eat into it. */
.qrbox{display:flex;justify-content:center;margin-top:14px}
.qrbox svg{width:240px;height:240px;max-width:100%;background:#fff;border-radius:10px;display:block}
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
  <div class="who"><h1>短信转发</h1><span class="ver" id="ver"></span></div>
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
  <!-- Deliberately here and not only on a module card: this is the path for when there IS no
       card — the module is offline, blocked, or was forgotten, or the page never saw it. -->
  <button class="mitem" id="smsCmdBtn" type="button" role="menuitem">短信指令</button>
  <a class="mitem danger" href="/logout" role="menuitem">退出</a>
</div>
<main><div id="beat"></div><div id="kaStatus"></div><div id="outbox"></div><ul id="list"><li class="empty">加载中…</li></ul></main>
<!-- 更新脚本… on a module card opens this; which module is kept in data-dev while the picker is up. -->
<input type="file" id="otaFile" accept=".lua,text/x-lua,text/plain" hidden>

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

<dialog id="smsDlg">
  <h2>短信指令</h2>
  <p>网页或域名都够不着模组时用这条：把下面生成的那一行发给模组的 SIM 卡号，模组验签后执行。
     整行在这台设备上生成并签名，号码只用来做二维码，不上传。</p>
  <label class="fl" for="smsTo">目标号码（模组那张 SIM）</label>
  <input id="smsTo" class="fs" placeholder="模组的手机号" inputmode="tel" autocomplete="off">
  <label class="fl" for="smsCmdSel">指令</label>
  <select id="smsCmdSel" class="fs">
    <option value="status">状态</option>
    <option value="reboot">重启</option>
    <option value="bases">改域名</option>
    <option value="reset">恢复默认域名</option>
    <option value="ota">更新脚本</option>
    <option value="otaclear">清除更新</option>
  </select>
  <label class="fl" for="smsQrFmt">二维码格式（扫不出来 / 号码跑进正文，就换一个）</label>
  <select id="smsQrFmt" class="fs">
    <option value="smsto">SMSTO:（多数扫码 App、Google 相机）</option>
    <option value="sms">sms:?body=（Android 原生相机、部分国产 ROM）</option>
    <option value="smsamp">sms:&amp;body=（iPhone 相机）</option>
    <option value="text">纯文本（扫出来自己复制，最保险）</option>
  </select>
  <div id="smsUrlWrap" hidden>
    <label class="fl" for="smsUrl">新的服务器地址，多个用逗号分隔（必须 https://）</label>
    <input id="smsUrl" class="fs" placeholder="https://a.example,https://b.example" spellcheck="false" autocomplete="off">
  </div>
  <div id="smsOtaWrap" hidden>
    <label class="fl" for="smsOtaFile">脚本文件（文件名决定替换哪个：gw.lua / gcm.lua）</label>
    <input type="file" id="smsOtaFile" class="fs" accept=".lua,text/x-lua,text/plain">
    <div id="smsOtaLast"></div>
    <p id="smsOtaNote" class="fh"></p>
  </div>
  <div class="row">
    <button type="button" id="smsClose">关闭</button>
    <button type="button" class="primary" id="smsGo">生成</button>
  </div>
  <div id="smsOut" hidden>
    <div id="smsLine" class="smsline"></div>
    <div class="row" style="justify-content:flex-start;margin-top:10px">
      <button type="button" id="smsCopy">复制</button>
    </div>
    <div id="smsQr" class="qrbox"></div>
    <p id="smsHint" class="fh"></p>
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

// Stamped per deploy from the version_metadata binding, so it can never go stale the way a
// hand-bumped version string does. Empty only if the binding is missing (old wrangler.toml).
(() => {
  const iso = "__BUILT__";
  const el = document.getElementById("ver");
  const d = iso ? new Date(iso) : null;
  if (!el || !d || isNaN(d)) return;
  const p = (n) => String(n).padStart(2, "0");
  el.textContent = "发布于 " + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
  el.title = d.toLocaleString();
})();

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
// The module polls on a schedule, not continuously: 120 s in the UTC 06-22 window and 600 s
// outside it. Judging it by the phone's 20-minute rule paints the card red every night for a
// module that is working perfectly — and worst, at exactly the hour the owner last checks the
// page. Four missed slow-tier polls is a real fault; two is bedtime.
const MODULE_ONLINE_MS = 45 * 60000;
const ago = (ms) => {
  const m = Math.floor(ms / 60000);
  if (m < 1) return "不到 1 分钟";
  if (m < 60) return m + " 分钟";
  const h = Math.floor(m / 60);
  return h < 24 ? h + " 小时" : Math.floor(h / 24) + " 天";
};

/* --- self-registered modules: trust, commands, script update --- */
// Last command per module id ({id, ts, payload, status, detail} or null), from /api/cmd/list.
// Fetched once per module, then only while its last command is still pending (the module acks
// within one poll of picking it up) or right after the web queued a new one — not every 10s for
// every device forever.
const CMDS = new Map();
const CMD_DIRTY = new Set();
const CMD_LABEL = { reboot: "重启", ota: "更新脚本", bases: "改域名" };
const CMD_STATE = { pending: "待执行", done: "已完成", failed: "失败" };

async function refreshCmd(dev){
  const cur = CMDS.get(dev);
  if (CMDS.has(dev) && !CMD_DIRTY.has(dev) && !(cur && cur.status === "pending")) return;
  try {
    const r = await fetch("/api/cmd/list?dev=" + encodeURIComponent(dev), { cache: "no-store" });
    if (!r.ok) return;
    const rows = await r.json();
    CMDS.set(dev, rows[0] || null);
    CMD_DIRTY.delete(dev);
  } catch {}
}

// One line for the card: "更新脚本 gw · 已完成 · 18234" / "重启 · 失败 · …". The payload is the
// server's plain JSON, so this needs no key.
function cmdSummary(c){
  if (!c) return "";
  let p = {}; try { p = JSON.parse(c.payload); } catch {}
  const what = (CMD_LABEL[p.type] || p.type || "命令") + (p.name ? " " + p.name : "");
  return [what, CMD_STATE[c.status] || c.status, c.detail || ""].filter(Boolean).join(" · ");
}

async function setTrust(id, status){
  const r = await fetch("/api/device/trust", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, status }),
  });
  if (r.status === 401) { location.href = "/login"; return; }
  if (!r.ok) { alert("操作失败：" + r.status); return; }
  lastBeatSig = null;
  renderBeat();
}

// Queue a command; the module runs it on its next poll. 409 means one is still waiting — the
// server allows one at a time, because most of them end in a reboot.
async function postCmd(dev, body){
  const r = await fetch("/api/cmd", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.assign({ dev }, body)),
  });
  if (r.status === 401) { location.href = "/login"; return false; }
  if (r.status === 409) { alert("这台设备还有一条命令没执行完，等它完成或先撤销。"); return false; }
  if (!r.ok) { alert("命令下发失败：" + r.status + " " + (await r.text().catch(() => ""))); return false; }
  CMD_DIRTY.add(dev);
  lastBeatSig = null;
  renderBeat();
  return true;
}

async function undoCmd(dev, id){
  const r = await fetch("/api/cmd/" + id, { method: "DELETE" });
  if (r.status === 401) { location.href = "/login"; return; }
  CMD_DIRTY.add(dev);
  lastBeatSig = null;
  renderBeat();
}

// The command signature. HMAC-SHA256 over name + a newline + the exact bytes under SMS_KEY —
// the same key that encrypts messages, and the one thing the server never has. (Written out in
// prose because this comment is inside the page template literal: a backslash-n here would be
// served as a real line break and split the comment in two.) The name is bound
// into the signature, so a file signed for gw can never be installed as gcm and an "ota"
// signature can never pass as a "bases" one. Used by 更新脚本 (name "gw"/"gcm", bytes = the
// file) and by 改域名 (name "bases", bytes = the normalised address list). The module
// recomputes it over what it received and refuses anything that doesn't match, so neither a
// Worker compromise nor an on-path attacker can push code or move the module elsewhere.
async function hmacHex(name, bytes){
  const hex = (localStorage.getItem("sms_key") || "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("未设置密钥");
  const k = await crypto.subtle.importKey("raw", hexToBytes(hex), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const prefix = new TextEncoder().encode(name + "\\n");
  const data = new Uint8Array(prefix.length + bytes.byteLength);
  data.set(prefix, 0); data.set(new Uint8Array(bytes), prefix.length);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
  return [...sig].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const otaFile = document.getElementById("otaFile");
otaFile.onchange = async () => {
  const dev = otaFile.dataset.dev, f = otaFile.files[0];
  otaFile.value = "";
  if (!dev || !f) return;
  // Which slot the file goes to comes from its name: the module keeps exactly gw.lua and gcm.lua.
  const m = /^(gw|gcm)\\.lua$/i.exec(f.name);
  if (!m) { alert("文件名必须是 gw.lua 或 gcm.lua（决定替换模组上的哪个脚本）。"); return; }
  const name = m[1].toLowerCase();
  if (!confirm("把 " + f.name + "（" + f.size + " 字节）推送到「" + (DEVS.get(dev)?.name || dev) + "」？模组校验签名后写入并重启。")) return;
  try {
    const bytes = await f.arrayBuffer();
    const hmac = await hmacHex(name, bytes);
    // The hmac rides along so it is stored beside the file: an SMS "#ota <slot> <hmac>" is
    // nothing but that value, and 短信指令 can then offer this upload without the file again.
    const r = await fetch("/api/ota/put?name=" + name + "&hmac=" + hmac, { method: "POST", body: bytes });
    if (r.status === 401) { location.href = "/login"; return; }
    if (!r.ok) { alert("上传失败：" + r.status + " " + (await r.text().catch(() => ""))); return; }
    await postCmd(dev, { type: "ota", name, hmac });
  } catch (e) {
    alert("更新脚本失败：" + (e && e.message ? e.message : e));
  }
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
      sims: Array.isArray(info?.s) ? info.s : [], caps: info?.c || null, gaps: info?.g || null, ver: info?.v || null, tr: info?.t || null, os: info?.os || null, ls: info?.ls || null,
      cap: info?.cap || null, pp: info?.pp || null, ln: info?.ln || null,
      // Module registry: status is server-side (the web sets it); the rest is the module's own
      // self-description, so the card can say which physical device this is.
      status: d.status || "trusted", module: !!d.module,
      imei: info?.imei || null, iccid: info?.iccid || null, fw: info?.fw || null, sver: info?.ver || null,
      // The module's own SIM number, when the firmware could read it off the card. Never shown
      // on the card — it is only the initial value the 短信指令 composer offers for 目标号码.
      num: info?.num || null,
      ota: info?.ota || null, boot: info?.boot ?? null,
    });
  }
  DEVS = next;
  for (const d of next.values()) if (d.module && d.status === "trusted") await refreshCmd(d.id);

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
      return [d.id, on, d.name, d.caps, d.gaps, d.sims, d.ver, d.tr, d.os, d.ls, on ? 0 : ago(nowB - d.ts),
        d.status, d.module, d.imei, d.iccid, d.fw, d.sver, d.ota, d.boot, cmdSummary(CMDS.get(d.id))];
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
    const on = age < (d.module ? MODULE_ONLINE_MS : ONLINE_MS);
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
    // A module that isn't trusted yet is the card you came to click, so it stands out; a blocked
    // one fades but stays listed — it is still registering, and 忘记 is how it really goes away.
    if (d.module && d.status === "pending") box.classList.add("pend");
    if (d.module && d.status === "blocked") box.classList.add("blk");
    box.title = ACTIVE_DEV === d.id ? "再点一次显示全部设备" : "只看这台设备";
    box.onclick = (e) => { if (!e.target.closest(".del,.dev-acts,.dev-cmd")) setActiveDev(d.id); };
    const top = document.createElement("div"); top.className = "dev-top";
    const dot = document.createElement("span");
    dot.textContent = "●"; dot.style.color = on ? "#22c55e" : "var(--danger)";
    const name = document.createElement("span"); name.className = "dev-name";
    name.textContent = d.name;
    // Trusted needs no badge — that is the state every phone has always been in.
    if (d.module && d.status !== "trusted") {
      const badge = document.createElement("span");
      badge.className = "dev-badge " + (d.status === "pending" ? "pend" : "blk");
      badge.textContent = d.status === "pending" ? "待信任" : "已拉黑";
      top.append(badge);
    }
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
    } else if ((canForward === true || d.module) && !on) {
      // Online + working needs no line — the green dot already says it. The reassurance is only
      // worth showing when the device is OFFLINE, so the red dot isn't misread as "stopped receiving".
      // The module needs it more than any phone does: its register blob carries no caps (name,
      // imei, iccid, imsi, num, fw, ver, ota, boot — no capability fields), so canForward is null
      // and without the d.module arm it got a red dot and no explanation at all. Inbound SMS is
      // pushed the moment it arrives, so a sleeping poll really does forward nothing more slowly.
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
    if (d.os && !d.module) {
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
    // The four send gates as the phone itself sees them — role / SEND_SMS / AppOps / SIM. They
    // fail independently (a granted permission with an IGNORED AppOp sends nothing and says
    // nothing), so a single "可发送 ✅" could never explain a failure. Red as soon as any is off.
    if (d.cap) {
      const txt = String(d.cap);
      const bad = txt.includes("role-") || txt.includes("send-") ||
        (txt.includes("op:") && !txt.includes("op:ALLOWED") && !txt.includes("op:DEFAULT"));
      const c = document.createElement("div");
      c.className = bad ? "dev-warn" : "dev-sims";
      c.textContent = "发送条件 " + txt;
      c.title = c.textContent;
      sub.append(c);
    }
    // What the notification listener last did, and with which package. "通知栏看得到但没转发" and
    // "根本没收到通知" look identical from here without it.
    if (d.ln) {
      const txt = String(d.ln);
      const l = document.createElement("div");
      l.className = txt.includes("已转发") ? "dev-sims" : "dev-warn";
      l.textContent = "上次通知 " + txt;
      l.title = l.textContent;
      sub.append(l);
    }
    // Did the phone's poll reach the server, and which send task did it last pick up? This is what
    // separates "网页的命令没到手机" from "手机收到了但发不出去" — previously indistinguishable.
    if (d.pp && d.pp.length > 1) {
      const err = String(d.pp[0] || ""), lastId = Number(d.pp[1]);
      if (err) {
        const e = document.createElement("div"); e.className = "dev-warn";
        e.textContent = "轮询失败 " + err;
        sub.append(e);
      }
      if (lastId >= 0) {
        const o = document.createElement("div"); o.className = "dev-sims";
        o.textContent = "最近取到发送任务 #" + lastId;
        sub.append(o);
      }
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
    if ((d.ver || d.tr) && !d.module) {
      const net = d.tr === "cell" ? "蜂窝" : (d.tr || "");
      const line = document.createElement("div"); line.className = "dev-net";
      line.textContent = [net, d.ver ? "v" + d.ver : ""].filter(Boolean).join(" · ");
      sub.append(line);
    }
    box.append(top, sub);
    if (d.module) {
      // Which physical module is this? Last 6 of IMEI/ICCID is enough to match the sticker on the
      // board or the SIM, and short enough to fit; the carrier already shows on the SIM line above.
      // Firmware / script / active OTA slot / boot-fail counter are what you look at before
      // deciding whether to push an update or just reboot.
      const idl = [d.imei ? "IMEI …" + String(d.imei).slice(-6) : "", d.iccid ? "ICCID …" + String(d.iccid).slice(-6) : ""].filter(Boolean);
      if (idl.length) {
        const l = document.createElement("div"); l.className = "dev-id";
        l.textContent = idl.join(" · "); l.title = l.textContent;
        sub.append(l);
      }
      const swl = [d.sver ? "脚本 " + d.sver : "", d.fw ? "固件 " + d.fw : "",
        // Both of these are only worth the width when they are NOT the healthy value: an active
        // OTA copy, or a module that has been failing to boot.
        d.ota && d.ota !== "-" ? "ota " + d.ota : "",
        Number(d.boot) > 0 ? "重启 " + d.boot : ""].filter(Boolean);
      if (swl.length) {
        const l = document.createElement("div"); l.className = "dev-id";
        l.textContent = swl.join(" · "); l.title = l.textContent;
        sub.append(l);
      }
      const acts = document.createElement("div"); acts.className = "dev-acts";
      const mk = (label, cls, fn) => {
        const b = document.createElement("button"); b.type = "button"; b.textContent = label;
        if (cls) b.className = cls;
        b.onclick = async (e) => { e.stopPropagation(); b.disabled = true; try { await fn(); } finally { b.disabled = false; } };
        acts.append(b);
      };
      const block = async () => {
        if (confirm("拉黑「" + d.name + "」？它将不能上报、也收不到发送任务，随时可再信任。")) await setTrust(d.id, "blocked");
      };
      if (d.status !== "trusted") mk("信任", "ok", () => setTrust(d.id, "trusted"));
      // A stranger's card offers 拉黑 as well: 忘记 only deletes the row, and the module is back as
      // 待信任 on its next attempt. Blocked rows also stop counting toward the pending cap.
      if (d.status === "pending") mk("拉黑", "bad", block);
      if (d.status === "trusted") {
        mk("重启", "", async () => { if (confirm("重启「" + d.name + "」？")) await postCmd(d.id, { type: "reboot" }); });
        mk("改域名…", "", async () => {
          // Signed with SMS_KEY like 更新脚本 is, and for a bigger reason: this is the one command
          // that can move the module to someone else's server for good. Without the key we cannot
          // sign, and the module would refuse it — so say so before asking for anything.
          if (!cryptoKey) { alert("请先点「密钥」填入 SMS_KEY —— 脚本要用它签名，模组才会接受。"); return; }
          const v = prompt("新的服务器地址，多个用逗号分隔（必须 https://）。模组保存后会重启：", location.origin);
          if (v == null) return;
          // Same rule as the server's okUrl: https, host[:port][/path], nothing the module's
          // "/api/…" join could trip over (no ?, #, quotes, escapes), trailing "/" dropped.
          const list = v.split(",").map((s) => s.trim().replace(/\\/+$/, "")).filter(Boolean);
          const okUrl = (s) => s.length <= 120 && /^https:\\/\\/[A-Za-z0-9.-]+(:[0-9]+)?(\\/[A-Za-z0-9._~\\/-]*)?$/.test(s);
          if (!list.length || list.length > 5 || !list.every(okUrl)) {
            alert("每个地址都要以 https:// 开头，只能是域名[:端口][/路径]（不能带 ?、# 或引号），最多 5 个，每个不超过 120 字符。"); return;
          }
          // Sign the normalised list — exactly the bytes the server stores and the module verifies.
          const value = list.join(",");
          try {
            const hmac = await hmacHex("bases", new TextEncoder().encode(value));
            await postCmd(d.id, { type: "bases", value, hmac });
          } catch (e) {
            alert("改域名失败：" + (e && e.message ? e.message : e));
          }
        });
        mk("更新脚本…", "", async () => {
          if (!cryptoKey) { alert("请先点「密钥」填入 SMS_KEY —— 脚本要用它签名，模组才会接受。"); return; }
          otaFile.dataset.dev = d.id;
          otaFile.click();
        });
        mk("拉黑", "bad", block);
      }
      // Always offered, whatever the trust state: a blocked, never-trusted or long-offline
      // module is exactly the one the web can no longer reach, and SMS is the way back in.
      mk("短信…", "", () => openSmsDlg(d.id));
      box.append(acts);
      const c = CMDS.get(d.id);
      if (d.status === "trusted" && c) {
        const l = document.createElement("div"); l.className = "dev-cmd" + (c.status === "failed" ? " fail" : "");
        l.textContent = cmdSummary(c);
        if (c.status === "pending") {
          const u = document.createElement("span"); u.className = "undo"; u.textContent = "撤销";
          u.title = "模组还没取走这条命令，可以撤回";
          u.onclick = (e) => { e.stopPropagation(); undoCmd(d.id, c.id); };
          l.append(u);
        }
        box.append(l);
      }
    }
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
    // A pending/blocked module can't claim a send; offering its SIM would just park the row.
    if (d.status && d.status !== "trusted") continue;
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

/* ============================================================== QR encoder ==
   Inlined, and this is the one place on the page where that is load-bearing: the 短信指令
   composer below exists for the moment the Worker or the domain cannot be reached, so a CDN
   would be exactly as unreachable as everything else it is meant to rescue. Byte mode, ECC
   level M, versions 1-10 — enough for every command this dialog can build (213 bytes at the
   top end) and small enough to read in one sitting.

   Everything the spec says about whether a phone can actually read the result is here:
   mode+length header, terminator and EC/11 padding, Reed-Solomon per block with the real
   block layout, interleaving, function patterns, BCH-protected format and (v7+) version
   info, and all eight data masks scored by the four penalty rules — the mask is chosen, not
   hardcoded, because a bad one on a given payload is a QR that will not scan.            */

// [data codewords, EC codewords per block, group-1 blocks, group-2 blocks] per version, ECC M.
// A group-2 block holds exactly one data codeword more than a group-1 one.
const QR_ECC = [
  [16, 10, 1, 0], [28, 16, 1, 0], [44, 26, 1, 0], [64, 18, 2, 0], [86, 24, 2, 0],
  [108, 16, 4, 0], [124, 18, 4, 0], [154, 22, 2, 2], [182, 22, 3, 2], [216, 26, 4, 1],
];
// Alignment-pattern centre coordinates per version; every pair of them carries a pattern
// except the three that would sit on a finder.
const QR_ALIGN = [[], [6,18], [6,22], [6,26], [6,30], [6,34], [6,22,38], [6,24,42], [6,26,46], [6,28,50]];

// GF(256) with the QR primitive polynomial 0x11d, as log/antilog tables — the doubled exp
// table lets a product skip the modulo on the exponent.
const GF_EXP = new Uint8Array(512), GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) { GF_EXP[i] = x; GF_LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();
const gfMul = (a, b) => (a && b) ? GF_EXP[GF_LOG[a] + GF_LOG[b]] : 0;

// The RS generator polynomial of degree n, highest coefficient first.
function qrRsGen(n){
  let g = [1];
  for (let i = 0; i < n; i++){
    const next = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++){ next[j] ^= g[j]; next[j + 1] ^= gfMul(g[j], GF_EXP[i]); }
    g = next;
  }
  return g;
}
// The remainder of data(x)*x^ecLen over the generator: the block's EC codewords.
function qrRs(data, ecLen){
  const g = qrRsGen(ecLen), res = new Uint8Array(data.length + ecLen);
  res.set(data);
  for (let i = 0; i < data.length; i++){
    const f = res[i];
    if (!f) continue;
    for (let j = 0; j < g.length; j++) res[i + j] ^= gfMul(g[j], f);
  }
  return res.slice(data.length);
}

// The eight data masks, by their spec condition (x = column, y = row).
const QR_MASK = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x, y) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
  (x, y) => (x * y) % 2 + (x * y) % 3 === 0,
  (x, y) => ((x * y) % 2 + (x * y) % 3) % 2 === 0,
  (x, y) => ((x + y) % 2 + (x * y) % 3) % 2 === 0,
];

// The four penalty rules, lower is better: long same-colour runs, 2x2 blocks, anything that
// looks like a finder, and an unbalanced dark/light ratio.
function qrPenalty(mod, size){
  let p = 0;
  for (let t = 0; t < 2; t++){
    for (let i = 0; i < size; i++){
      let line = "";
      for (let j = 0; j < size; j++) line += (t === 0 ? mod[i][j] : mod[j][i]) ? "1" : "0";
      let run = 1;
      for (let j = 1; j < size; j++){
        if (line[j] === line[j - 1]) run++;
        else { if (run >= 5) p += 3 + run - 5; run = 1; }
      }
      if (run >= 5) p += 3 + run - 5;
      // 1:1:3:1:1 with four light modules on one side — the finder's own signature, which is
      // why a scanner mistakes it for one.
      for (let j = 0; j + 11 <= size; j++){
        const s = line.slice(j, j + 11);
        if (s === "10111010000" || s === "00001011101") p += 40;
      }
    }
  }
  for (let y = 0; y + 1 < size; y++) for (let x = 0; x + 1 < size; x++){
    const v = mod[y][x];
    if (v === mod[y][x + 1] && v === mod[y + 1][x] && v === mod[y + 1][x + 1]) p += 3;
  }
  let dark = 0;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) dark += mod[y][x];
  p += Math.floor(Math.abs(dark * 100 / (size * size) - 50) / 5) * 10;
  return p;
}

// → {size, mod} (mod[y][x] = 0|1), or null when the payload does not fit version 10.
function qrEncode(str){
  const bytes = new TextEncoder().encode(str);
  let ver = 0;
  for (let v = 1; v <= 10; v++){
    if (bytes.length * 8 + 4 + (v < 10 ? 8 : 16) <= QR_ECC[v - 1][0] * 8) { ver = v; break; }
  }
  if (!ver) return null;
  const dcw = QR_ECC[ver - 1][0], ecLen = QR_ECC[ver - 1][1];
  const g1 = QR_ECC[ver - 1][2], g2 = QR_ECC[ver - 1][3], nb = g1 + g2;

  // --- bit stream: mode 0100, the length, the bytes, a 4-bit terminator, then EC/11 padding
  const bits = [];
  const put = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1); };
  put(4, 4);
  put(bytes.length, ver < 10 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  for (let i = 0; i < 4 && bits.length < dcw * 8; i++) bits.push(0);
  while (bits.length % 8) bits.push(0);
  const data = new Uint8Array(dcw);
  for (let i = 0; i < bits.length; i += 8){
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    data[i / 8] = b;
  }
  for (let i = bits.length / 8, pad = 0; i < dcw; i++, pad++) data[i] = pad % 2 ? 0x11 : 0xec;

  // --- split into blocks, add EC to each, interleave (data first, then EC)
  const perBlk = Math.floor(dcw / nb);
  const blocks = [], ecs = [];
  for (let i = 0, off = 0; i < nb; i++){
    const len = perBlk + (i >= g1 ? 1 : 0);
    const blk = data.slice(off, off + len); off += len;
    blocks.push(blk); ecs.push(qrRs(blk, ecLen));
  }
  const out = [];
  for (let i = 0; i <= perBlk; i++) for (const b of blocks) if (i < b.length) out.push(b[i]);
  for (let i = 0; i < ecLen; i++) for (const e of ecs) out.push(e[i]);

  // --- the matrix: function patterns first, so data placement knows what to skip
  const size = ver * 4 + 17;
  const mod = [], fun = [];
  for (let i = 0; i < size; i++){ mod.push(new Array(size).fill(0)); fun.push(new Array(size).fill(0)); }
  const setF = (x, y, v) => { if (x >= 0 && y >= 0 && x < size && y < size){ mod[y][x] = v ? 1 : 0; fun[y][x] = 1; } };
  // Finder + its separator in one pass: ring distance 0-1 and 3 are dark, 2 is the light ring,
  // 4 is the separator.
  const finder = (ox, oy) => {
    for (let dy = -1; dy <= 7; dy++) for (let dx = -1; dx <= 7; dx++){
      const d = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
      setF(ox + dx, oy + dy, d !== 2 && d <= 3);
    }
  };
  finder(0, 0); finder(size - 7, 0); finder(0, size - 7);
  for (let i = 8; i < size - 8; i++){ setF(i, 6, i % 2 === 0); setF(6, i, i % 2 === 0); }
  const al = QR_ALIGN[ver - 1];
  for (const cy of al) for (const cx of al){
    if ((cx === 6 && cy === 6) || (cx === 6 && cy === size - 7) || (cx === size - 7 && cy === 6)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++)
      setF(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  // Format info: 5 data bits (ECC M = 00, then the mask) protected by BCH(15,5) over 0x537 and
  // XORed with 0x5412 so an all-zero format can never look valid. Drawn twice.
  const drawFormat = (mask) => {
    const d5 = mask;                       // ECC M contributes 0 to the high two bits
    let rem = d5;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const f = ((d5 << 10) | rem) ^ 0x5412;
    const bit = (i) => (f >>> i) & 1;
    for (let i = 0; i <= 5; i++) setF(8, i, bit(i));
    setF(8, 7, bit(6)); setF(8, 8, bit(7)); setF(7, 8, bit(8));
    for (let i = 9; i < 15; i++) setF(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) setF(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) setF(8, size - 15 + i, bit(i));
    setF(8, size - 8, 1);                  // the dark module, always
  };
  drawFormat(0);                           // reserve the cells; the real bits go in below
  if (ver >= 7){
    // Version info: 6 bits + BCH(18,6) over 0x1f25, in two 3x6 blocks by the finders.
    let rem = ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const vbits = (ver << 12) | rem;
    for (let i = 0; i < 18; i++){
      const b = (vbits >>> i) & 1, a = size - 11 + i % 3, c = Math.floor(i / 3);
      setF(a, c, b); setF(c, a, b);
    }
  }
  // --- data: two columns at a time, bottom-right upward, zigzagging, skipping column 6
  let bi = 0;
  for (let right = size - 1; right >= 1; right -= 2){
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++){
      for (let j = 0; j < 2; j++){
        const x = right - j;
        const y = (((right + 1) & 2) === 0) ? size - 1 - vert : vert;
        if (!fun[y][x] && bi < out.length * 8){
          mod[y][x] = (out[bi >>> 3] >>> (7 - (bi & 7))) & 1;
          bi++;
        }
      }
    }
  }
  // --- all eight masks, scored; keep the best. XOR is its own inverse, so each trial is undone
  // by re-applying it.
  let best = -1, bestP = Infinity;
  for (let m = 0; m < 8; m++){
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fun[y][x] && QR_MASK[m](x, y)) mod[y][x] ^= 1;
    drawFormat(m);
    const p = qrPenalty(mod, size);
    if (p < bestP) { bestP = p; best = m; }
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fun[y][x] && QR_MASK[m](x, y)) mod[y][x] ^= 1;
  }
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fun[y][x] && QR_MASK[best](x, y)) mod[y][x] ^= 1;
  drawFormat(best);
  return { size, mod, ver, mask: best };
}

// One SVG path of horizontal runs, on a white rect that includes the 4-module quiet zone —
// crisp at any size, no canvas, and nothing to load.
function qrSvg(m){
  const q = 4, total = m.size + q * 2;
  let d = "";
  for (let y = 0; y < m.size; y++){
    let x = 0;
    while (x < m.size){
      if (!m.mod[y][x]) { x++; continue; }
      let w = 1;
      while (x + w < m.size && m.mod[y][x + w]) w++;
      d += "M" + (x + q) + " " + (y + q) + "h" + w + "v1h-" + w + "z";
      x += w;
    }
  }
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 " + total + " " + total);
  svg.setAttribute("shape-rendering", "crispEdges");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "短信二维码");
  const bg = document.createElementNS(NS, "rect");
  bg.setAttribute("width", String(total)); bg.setAttribute("height", String(total)); bg.setAttribute("fill", "#fff");
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", d); path.setAttribute("fill", "#000");
  svg.append(bg, path);
  return svg;
}

/* --- 短信指令: compose a signed SMS command, and hand the phone a QR of it -----------------
   The same wire format main.lua verifies (sms_split / sms_signed) and luatos/sms-sign.sh
   prints: "<body> <mac>", one space, no trailing whitespace, mac = the first 16 hex of
   HMAC-SHA256 over "sms" + a newline + the body under SMS_KEY. Nothing is sent from here —
   the point of the channel is that there may be nothing left to send to. */
const smsDlg = document.getElementById("smsDlg");
const smsToIn = document.getElementById("smsTo");
const smsCmdSel = document.getElementById("smsCmdSel");
const smsQrFmt = document.getElementById("smsQrFmt");
try { const f = localStorage.getItem("sms_qr_fmt"); if (f) smsQrFmt.value = f; } catch {}
const smsUrlIn = document.getElementById("smsUrl");
const smsOtaFile = document.getElementById("smsOtaFile");
const smsOtaLast = document.getElementById("smsOtaLast");
const smsOtaNote = document.getElementById("smsOtaNote");
const smsOut = document.getElementById("smsOut");
const smsLine = document.getElementById("smsLine");
const smsQr = document.getElementById("smsQr");
const smsHint = document.getElementById("smsHint");
let SMS_DEV = "";     // the module the dialog was opened for; "" = opened from the ⋯ menu
let SMS_OTA = null;   // {name, hmac} once a script is staged — uploaded just now, or last time

// Remembered per module: two modules are two SIMs. The bare key is the no-device case, which
// is also the one that matters most — the card may be gone, that is why you are here.
const smsToKey = (dev) => "sms_to:" + (dev || "");

function smsCmdChanged(){
  const k = smsCmdSel.value;
  document.getElementById("smsUrlWrap").hidden = k !== "bases";
  document.getElementById("smsOtaWrap").hidden = k !== "ota";
  smsOut.hidden = true;                 // a stale line under a freshly changed command misleads
}

// 「用上次上传的」. An SMS "#ota" carries nothing but the file's hmac, so a script already
// staged on the Worker needs no upload at all — but only if its hmac was stored with it.
// Anything put there before /api/ota/put learned the param has none, and gets no shortcut.
async function smsOtaShortcuts(){
  smsOtaLast.textContent = "";
  let meta = null;
  try { const r = await fetch("/api/ota/meta", { cache: "no-store" }); if (r.ok) meta = await r.json(); } catch {}
  if (!meta) return;
  for (const name of ["gw", "gcm"]) {
    const m = meta[name];
    if (!m || !/^[0-9a-f]{64}$/i.test(String(m.hmac || ""))) continue;
    const b = document.createElement("button");
    b.type = "button"; b.className = "out wide";
    b.textContent = "用上次上传的 " + name + ".lua（" + m.size + " 字节）";
    b.onclick = () => {
      SMS_OTA = { name, hmac: String(m.hmac).toLowerCase() };
      smsOtaNote.textContent = "用服务器上已有的 " + name + ".lua，签名 " + SMS_OTA.hmac.slice(0, 16) + "…";
    };
    smsOtaLast.append(b);
  }
}

async function openSmsDlg(dev){
  // The same refusal 更新脚本 gives: with no key nothing can be signed, and the module would
  // ignore whatever this dialog produced.
  if (!cryptoKey) { alert("请先点「密钥」填入 SMS_KEY —— 脚本要用它签名，模组才会接受。"); return; }
  SMS_DEV = dev || "";
  SMS_OTA = null;
  let to = "";
  try { to = localStorage.getItem(smsToKey(SMS_DEV)) || ""; } catch {}
  // The module reports its own SIM number in the register blob when the firmware can read it
  // off the card, so the common case is: open, pick, generate.
  if (!to && SMS_DEV) to = String((DEVS.get(SMS_DEV) || {}).num || "");
  if (!to) { try { to = localStorage.getItem(smsToKey("")) || ""; } catch {} }
  smsToIn.value = to;
  smsUrlIn.value = location.origin;
  smsOtaFile.value = "";
  smsOtaNote.textContent = "";
  smsOtaLast.textContent = "";
  smsQr.textContent = "";
  smsCmdChanged();
  smsDlg.showModal();
  smsOtaShortcuts();                    // needs the Worker; the rest of the dialog does not
}

smsCmdSel.onchange = smsCmdChanged;
document.getElementById("smsCmdBtn").onclick = () => openSmsDlg("");
document.getElementById("smsClose").onclick = () => smsDlg.close();

smsOtaFile.onchange = async () => {
  const f = smsOtaFile.files[0];
  if (!f) return;
  // Which slot the file goes to comes from its name, exactly like the 更新脚本 flow.
  const m = /^(gw|gcm)\\.lua$/i.exec(f.name);
  if (!m) { smsOtaFile.value = ""; alert("文件名必须是 gw.lua 或 gcm.lua（决定替换模组上的哪个脚本）。"); return; }
  const name = m[1].toLowerCase();
  smsOtaNote.textContent = "上传中…";
  try {
    const bytes = await f.arrayBuffer();
    const hmac = await hmacHex(name, bytes);
    // The module still DOWNLOADS the script from the Worker — only the command travels by SMS —
    // so the file has to be staged first. That is the one part of this flow the Worker is
    // needed for, which is why 更新脚本 over SMS is for a broken module, not a broken server.
    const r = await fetch("/api/ota/put?name=" + name + "&hmac=" + hmac, { method: "POST", body: bytes });
    if (r.status === 401) { location.href = "/login"; return; }
    if (!r.ok) { smsOtaNote.textContent = "上传失败：" + r.status + " " + (await r.text().catch(() => "")); return; }
    SMS_OTA = { name, hmac };
    smsOtaNote.textContent = name + ".lua 已上传（" + f.size + " 字节），模组会从 Worker 下载它。";
    smsOtaShortcuts();
  } catch (e) { smsOtaNote.textContent = "上传失败：" + (e && e.message ? e.message : e); }
};

document.getElementById("smsGo").onclick = async () => {
  const kind = smsCmdSel.value;
  let body = "";
  if (kind === "status") body = "#status";
  else if (kind === "reboot") body = "#reboot";
  else if (kind === "reset") body = "#url reset";
  else if (kind === "otaclear") body = "#ota clear";
  else if (kind === "bases") {
    // The rule 改域名 already uses, and the server's okUrl: https, host[:port][/path], nothing
    // the module's "/api/…" join could trip over, trailing "/" dropped. Sign the NORMALISED
    // list, because that is the value the module will store and compare against.
    const list = smsUrlIn.value.split(",").map((s) => s.trim().replace(/\\/+$/, "")).filter(Boolean);
    const okUrl = (s) => s.length <= 120 && /^https:\\/\\/[A-Za-z0-9.-]+(:[0-9]+)?(\\/[A-Za-z0-9._~\\/-]*)?$/.test(s);
    if (!list.length || list.length > 5 || !list.every(okUrl)) {
      alert("每个地址都要以 https:// 开头，只能是域名[:端口][/路径]（不能带 ?、# 或引号），最多 5 个，每个不超过 120 字符。"); return;
    }
    body = "#url " + list.join(",");
  } else if (kind === "ota") {
    if (!SMS_OTA) { alert("先选一个 gw.lua / gcm.lua 上传，或用上次上传的。"); return; }
    body = "#ota " + SMS_OTA.name + " " + SMS_OTA.hmac;
  }
  let line;
  try {
    // hmacHex already signs "<name>" + a newline + the bytes, so the SMS domain tag is just
    // the name "sms" — and the first 16 hex of it is the mac the device compares.
    line = body + " " + (await hmacHex("sms", new TextEncoder().encode(body))).slice(0, 16);
  } catch (e) { alert("签名失败：" + (e && e.message ? e.message : e)); return; }
  smsLine.textContent = line;
  try { localStorage.setItem(smsToKey(SMS_DEV), smsToIn.value.trim()); } catch {}
  smsQr.textContent = "";
  const to = norm(smsToIn.value);
  let hint;
  if (!to) {
    hint = "没填号码，就只有上面这行 —— 复制它，从任何一部手机发给模组的 SIM 卡号即可。";
  } else {
    // No QR-to-SMS convention is universal: SMSTO: is the zxing one most scanner apps take,
    // Android's own camera wants sms:<n>?body=, iOS sms:<n>&body=, and WeChat/Alipay understand
    // none of them and hand the whole string over as text. Offer all four and let the phone that
    // is actually in the room decide — the choice is remembered, so it is a one-time fiddle.
    const fmt = smsQrFmt.value;
    const payload =
      fmt === "sms"    ? "sms:" + to + "?body=" + encodeURIComponent(line) :
      fmt === "smsamp" ? "sms:" + to + "&body=" + encodeURIComponent(line) :
      fmt === "text"   ? line :
                         "SMSTO:" + to + ":" + line;
    try { localStorage.setItem("sms_qr_fmt", fmt); } catch {}
    const qr = qrEncode(payload);
    if (qr) {
      smsQr.append(qrSvg(qr));
      hint = fmt === "text"
        ? "扫出来的就是这行文字，复制到短信里发给模组即可（号码要自己填）。"
        : "用手机扫码会打开短信编辑界面，号码和内容已填好，点发送即可。号码跑进了正文、或者扫不出来，就在上面换一个二维码格式。";
    } else {
      // Refused, never truncated: half a command with a good-looking mac is worse than none.
      hint = "这行太长，二维码装不下（上限 213 字节）—— 复制上面那行自己发。";
    }
  }
  // Same budget warning sms-sign.sh prints on stderr, at the same threshold (body + space + the
  // 16-char mac, over 160). It still sends, but as a concatenated SMS the module has to reassemble
  // — and on the break-glass channel a command that silently does nothing is the worst outcome.
  if (line.length > 160) hint += "（这行 " + line.length + " 字，超过单条短信 160 字的额度：会被拆成多条发出，模组未必拼得回来 —— 能短就短。）";
  smsHint.textContent = hint;
  smsOut.hidden = false;
};

document.getElementById("smsCopy").onclick = async (e) => {
  const b = e.currentTarget;
  try {
    await navigator.clipboard.writeText(smsLine.textContent);
    b.textContent = "已复制";
    setTimeout(() => { b.textContent = "复制"; }, 1200);
  } catch {
    // Same fallback as the verification-code copy: the clipboard needs a focused document and
    // a secure context and is refused outright in some browsers. Select the line instead, so
    // Cmd/Ctrl+C still works rather than leaving the tap looking broken.
    const r = document.createRange();
    r.selectNodeContents(smsLine);
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(r);
  }
};

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
