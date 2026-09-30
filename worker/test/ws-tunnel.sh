#!/usr/bin/env bash
# The modules' WebSocket tunnel (index.js class Hub) against a LOCAL wrangler dev server, with
# Node's built-in WebSocket playing the Air780EHV. Nothing here touches the remote Worker or D1.
#
#   worker/test/ws-tunnel.sh            # port 8789, fresh .wrangler/state
#
# Needs: node ≥ 22, npx wrangler, curl, openssl, and worker/.dev.vars (SEND_TOKEN, WEB_USER,
# WEB_PASS, SESSION_SECRET). Prints one ✅ per check; exits non-zero on the first ❌.
set -euo pipefail

cd "$(dirname "$0")/.."      # worker/
PORT=${PORT:-8789}
BASE="http://127.0.0.1:$PORT"
WR="npx wrangler"
TMP=$(mktemp -d)
LOG="$TMP/wrangler.log"
WPID=""

pass() { echo "✅ $1"; }
fail() { echo "❌ $1"; [ -n "${2:-}" ] && echo "   got: $2"; [ -n "$WPID" ] && { echo "--- wrangler log tail ---"; tail -20 "$LOG"; }; exit 1; }
cleanup() {
    if [ -n "$WPID" ]; then kill "$WPID" 2>/dev/null || true; pkill -P "$WPID" 2>/dev/null || true; fi
    lsof -ti "tcp:$PORT" 2>/dev/null | xargs kill 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT
val() { sed -n "s/^$1=//p" .dev.vars | head -1 | tr -d '\r"'; }

[ -f .dev.vars ] || fail ".dev.vars missing in worker/"
WEB_USER=$(val WEB_USER); WEB_PASS=$(val WEB_PASS)
TOPIC=$(sed -n 's/^TOPIC = "\(.*\)"/\1/p' wrangler.toml)

node --check src/index.js && pass "node --check src/index.js"
rm -rf .wrangler/state
$WR d1 execute sms --local --file=schema.sql >/dev/null 2>&1 || fail "schema.sql failed to apply"
for c in "ALTER TABLE devices ADD COLUMN auth TEXT" "ALTER TABLE devices ADD COLUMN status TEXT NOT NULL DEFAULT 'trusted'"; do
    $WR d1 execute sms --local --command "$c" >/dev/null 2>&1 || true
done
$WR dev --port "$PORT" --local >"$LOG" 2>&1 &
WPID=$!
for i in $(seq 1 90); do
    curl -s -o /dev/null "$BASE/api/vapid" 2>/dev/null && break
    kill -0 "$WPID" 2>/dev/null || fail "wrangler dev exited early" "$(tail -20 "$LOG")"
    sleep 1
done
pass "wrangler dev up on :$PORT"

DEV=$(openssl rand -hex 8)
SECRET=$(openssl rand -hex 16)
curl -s -o /dev/null -X POST "$BASE/api/register?dev=$DEV" -H "Authorization: Bearer $SECRET" --data-binary "v1:x"
# The cookie is Secure, which curl will not send back over http — so it is carried by hand.
COOKIE=$(curl -s -D - -o /dev/null -X POST "$BASE/login" --data-urlencode "user=$WEB_USER" --data-urlencode "pass=$WEB_PASS" \
    | sed -n 's/^[Ss]et-[Cc]ookie: \(sms_session=[^;]*\).*/\1/p' | tr -d '\r')
[ -n "$COOKIE" ] || fail "web login"
curl -s -o /dev/null -X POST "$BASE/api/device/trust" -H "Cookie: $COOKIE" -H "Content-Type: application/json" \
    --data "{\"id\":\"$DEV\",\"status\":\"trusted\"}"
pass "module registered and trusted"

BASE="$BASE" DEV="$DEV" SECRET="$SECRET" TOPIC="$TOPIC" COOKIE="$COOKIE" node --input-type=module -e '
const { BASE, DEV, SECRET, TOPIC, COOKIE } = process.env;
const WS = BASE.replace(/^http/, "ws") + "/api/ws?dev=" + DEV;
const AUTH = "Bearer " + SECRET;
const pass = (m) => console.log("✅ " + m);
const fail = (m, got) => { console.log("❌ " + m + (got === undefined ? "" : "\n   got: " + JSON.stringify(got))); process.exit(1); };
const eq = (m, got, want) => JSON.stringify(got) === JSON.stringify(want) ? pass(m) : fail(m + " (want " + JSON.stringify(want) + ")", got);

function open(url, headers) {
  return new Promise((res) => {
    const ws = new WebSocket(url, { headers });
    ws.inbox = [];
    ws.onmessage = (e) => { ws.inbox.push(String(e.data)); ws.wake?.(); };
    ws.onopen = () => res(ws);
    ws.onerror = () => res(null);
    ws.onclose = (e) => { ws.closed = e.code; ws.wake?.(); };
  });
}
// Next frame matching pred, or null after ms.
async function next(ws, pred, ms = 5000) {
  const end = Date.now() + ms;
  for (;;) {
    const i = ws.inbox.findIndex(pred);
    if (i >= 0) return ws.inbox.splice(i, 1)[0];
    const left = end - Date.now();
    if (left <= 0) return null;
    await new Promise((r) => { ws.wake = r; setTimeout(r, left); });
  }
}
const meta = (f) => JSON.parse(f.slice(0, f.indexOf("\n") < 0 ? f.length : f.indexOf("\n")));
let seq = 0;
// Tunnelled request → {c, n, body} with the parts reassembled.
async function tunnel(ws, m, p, body = "", t = "", auth = AUTH) {
  const i = ++seq;
  ws.send(JSON.stringify({ i, m, p, a: auth, t }) + "\n" + body);
  const parts = [];
  let c, n = 1;
  while (parts.length < n) {
    const f = await next(ws, (x) => x.startsWith("{\"i\":" + i + ","));
    if (!f) fail("no reply to " + p);
    const h = meta(f); c = h.c; n = h.n;
    if (Buffer.byteLength(f) > 8000) fail("a frame past the module 8 KB buffer", Buffer.byteLength(f));
    parts[h.k] = f.slice(f.indexOf("\n") + 1);
  }
  return { c, n, body: parts.join("") };
}

eq("no bearer → no socket", await open(WS, {}), null);
eq("wrong bearer → no socket", await open(WS, { Authorization: "Bearer " + "0".repeat(32) }), null);
const ws = await open(WS, { Authorization: AUTH });
ws ? pass("socket opens with the module bearer") : fail("socket did not open");

let r = await tunnel(ws, "GET", "/api/poll?dev=" + DEV);
eq("tunnelled poll = the HTTPS poll", [r.c, JSON.parse(r.body)], [200, { status: "trusted", rows: [], cmd: null }]);
r = await tunnel(ws, "GET", "/api/status");
eq("a web route is not tunnelled (c=0: use HTTPS)", r.c, 0);
r = await tunnel(ws, "GET", "/api/poll?dev=" + "0".repeat(16));
eq("another module dev is not tunnelled", r.c, 0);
r = await tunnel(ws, "GET", "/api/poll?dev=" + DEV, "", "", "Bearer " + "1".repeat(32));
eq("the route still checks the bearer itself", r.c, 403);

// 5000 chars so the reply cannot fit one frame.
const payload = "v1:" + "A".repeat(2500) + "中".repeat(2500);
const sent = await fetch(BASE + "/api/send", { method: "POST", headers: { Cookie: COOKIE, "Content-Type": "application/json" },
  body: JSON.stringify({ payload, dev: DEV }) });
eq("web send accepted", sent.status, 200);
(await next(ws, (x) => x === "{\"t\":\"poll\"}")) ? pass("a queued send pokes the socket") : fail("no poke after /api/send");
r = await tunnel(ws, "GET", "/api/poll?dev=" + DEV);
const rows = JSON.parse(r.body).rows;
eq("the poll claims it, reply reassembled from " + r.n + " parts", [r.n > 2, rows.length, rows[0]?.payload === payload], [true, 1, true]);
r = await tunnel(ws, "POST", "/api/outbox/ack?dev=" + DEV, JSON.stringify({ id: rows[0].id, ok: true, detail: "SMS-x" }), "application/json");
eq("tunnelled ack", r.c, 200);

r = await tunnel(ws, "POST", "/" + TOPIC + "?dev=" + DEV, "v1:tunnelled-upload", "text/plain; charset=utf-8");
eq("tunnelled upload", [r.c, r.body], [200, "ok"]);
const list = await (await fetch(BASE + "/api/messages", { headers: { Cookie: COOKIE } })).json();
const msgs = list;
msgs.some((m) => m.body === "v1:tunnelled-upload") ? pass("and it is stored like an HTTPS upload") : fail("upload not in /api/messages", list);

const ws2 = await open(WS, { Authorization: AUTH });
await next(ws, () => false, 1000);
eq("a reconnect replaces the old socket", [!!ws2, ws.closed], [true, 1000]);
r = await tunnel(ws2, "GET", "/api/poll?dev=" + DEV);
eq("and the new one works", r.c, 200);
ws2.close();
process.exit(0);
'
