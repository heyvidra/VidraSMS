#!/usr/bin/env bash
# End-to-end test of the module registry (DESIGN-3 Part A) against a LOCAL wrangler dev server,
# with curl playing the Air780EHV module. Nothing here touches the remote Worker or D1.
#
#   worker/test/device-registry.sh            # uses port 8788, fresh .wrangler/state
#   PORT=8790 worker/test/device-registry.sh
#
# Needs: node, npx wrangler, curl, openssl, shasum, and worker/.dev.vars (SEND_TOKEN, WEB_USER,
# WEB_PASS — the same file wrangler dev reads). Prints one ✅ per check; exits non-zero on the
# first ❌. The dev server it starts is killed on exit, whatever the outcome.
set -euo pipefail

cd "$(dirname "$0")/.."      # worker/
PORT=${PORT:-8788}
BASE="http://127.0.0.1:$PORT"
WR="npx wrangler"
TMP=$(mktemp -d)
LOG="$TMP/wrangler.log"
WPID=""

pass() { echo "✅ $1"; }
fail() { echo "❌ $1"; [ -n "${2:-}" ] && echo "   got: $2"; [ -n "$WPID" ] && { echo "--- wrangler log tail ---"; tail -20 "$LOG"; }; exit 1; }
expect() { [ "$2" = "$3" ] && pass "$1" || fail "$1 (expected: $3)" "$2"; }

cleanup() {
    if [ -n "$WPID" ]; then
        kill "$WPID" 2>/dev/null || true
        pkill -P "$WPID" 2>/dev/null || true
    fi
    # wrangler dev spawns workerd as a grandchild; make sure nothing is left holding the port.
    lsof -ti "tcp:$PORT" 2>/dev/null | xargs kill 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

# --- helpers -------------------------------------------------------------------------------
# req METHOD PATH [curl args…] → CODE (http status) and BODY.
req() {
    local m=$1 p=$2 out; shift 2
    out=$(curl -s -X "$m" "$BASE$p" "$@" -w $'\n%{http_code}')
    CODE=${out##*$'\n'}
    BODY=${out%$'\n'*}
}
# jget JSON 'js expression over j' → the value (strings raw, everything else JSON-encoded).
jget() {
    node -e 'const j=JSON.parse(process.argv[1]); const v=eval(process.argv[2]); console.log(typeof v==="string"?v:JSON.stringify(v))' "$1" "$2"
}
# d1 SQL → the result rows as a JSON array (local D1 — the same sqlite file the dev server uses).
d1() {
    $WR d1 execute sms --local --json --command "$1" 2>/dev/null \
        | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{console.log(JSON.stringify(JSON.parse(s)[0].results||[]))})'
}
# Values from .dev.vars, never echoed.
val() { sed -n "s/^$1=//p" .dev.vars | head -1 | tr -d '\r"'; }

[ -f .dev.vars ] || fail ".dev.vars missing in worker/"
SEND_TOKEN=$(val SEND_TOKEN); WEB_USER=$(val WEB_USER); WEB_PASS=$(val WEB_PASS)
[ -n "$SEND_TOKEN" ] && [ -n "$WEB_USER" ] && [ -n "$WEB_PASS" ] || fail ".dev.vars must set SEND_TOKEN, WEB_USER, WEB_PASS"
TOPIC=$(sed -n 's/^TOPIC = "\(.*\)"/\1/p' wrangler.toml)

# --- 0. syntax, fresh local state, schema + migration -------------------------------------
node --check src/index.js && pass "node --check src/index.js"

rm -rf .wrangler/state
$WR d1 execute sms --local --file=schema.sql >/dev/null 2>&1 || fail "schema.sql failed to apply"
pass "schema.sql applied to a fresh local D1"
# Same tolerance setup.sh has: on a fresh schema both columns already exist, so the ALTERs must
# fail with exactly "duplicate column name" and nothing else.
alter() {
    local out
    if out=$($WR d1 execute sms --local --command "$1" 2>&1); then :
    elif echo "$out" | grep -q "duplicate column name"; then :
    else fail "migration: $1" "$out"; fi
}
alter "ALTER TABLE devices ADD COLUMN auth TEXT"
alter "ALTER TABLE devices ADD COLUMN status TEXT NOT NULL DEFAULT 'trusted'"
pass "ALTER TABLE migration tolerates duplicate columns"

$WR dev --port "$PORT" --local >"$LOG" 2>&1 &
WPID=$!
for i in $(seq 1 90); do
    curl -s -o /dev/null "$BASE/api/vapid" 2>/dev/null && break
    kill -0 "$WPID" 2>/dev/null || fail "wrangler dev exited early" "$(tail -20 "$LOG")"
    sleep 1
done
curl -s -o /dev/null "$BASE/api/vapid" || fail "dev server not reachable on $PORT" "$(tail -20 "$LOG")"
pass "wrangler dev up on :$PORT"

DEV=$(openssl rand -hex 8)        # 16 hex, like the module's fskv dev_id
SECRET=$(openssl rand -hex 16)    # 32 hex, like dev_secret
BLOB="v1:$(openssl rand -base64 48 | tr -d '\n')"
AUTH=(-H "Authorization: Bearer $SECRET")
JSON=(-H "Content-Type: application/json")

# --- 1. register ---------------------------------------------------------------------------
req POST "/api/register?dev=$DEV" "${AUTH[@]}" --data-binary "$BLOB"
expect "1. register → 200 pending" "$CODE $BODY" '200 {"status":"pending"}'
req POST "/api/register?dev=$DEV" "${AUTH[@]}" --data-binary "$BLOB"
expect "1. re-register, same secret → 200 pending" "$CODE $BODY" '200 {"status":"pending"}'
req POST "/api/register?dev=$DEV" -H "Authorization: Bearer $(openssl rand -hex 16)" --data-binary "$BLOB"
expect "1. register, different secret → 403" "$CODE $BODY" "403 forbidden"
req POST "/api/register?dev=$DEV" --data-binary "$BLOB"
expect "1. register, no bearer → 403" "$CODE" 403
req POST "/api/register?dev=not-hex" "${AUTH[@]}" --data-binary "$BLOB"
expect "1. register, bad dev id → 400" "$CODE" 400
for i in $(seq 1 19); do
    req POST "/api/register?dev=f111$(openssl rand -hex 6)" -H "Authorization: Bearer $(openssl rand -hex 16)" --data-binary "$BLOB"
    [ "$CODE" = 200 ] || fail "1. filler device $i" "$CODE $BODY"
done
req POST "/api/register?dev=$(openssl rand -hex 8)" -H "Authorization: Bearer $(openssl rand -hex 16)" --data-binary "$BLOB"
expect "1. 21st pending device → 429" "$CODE" 429
d1 "DELETE FROM devices WHERE id LIKE 'f111%'" >/dev/null

# --- 2. pending: cannot publish, poll says pending, heartbeat moves --------------------------
req POST "/$TOPIC?dev=$DEV" "${AUTH[@]}" --data-binary "$BLOB"
expect "2. publish while pending → 403" "$CODE $BODY" "403 forbidden"
TS0=$(jget "$(d1 "SELECT ts FROM devices WHERE id='$DEV'")" 'j[0].ts')
sleep 1
req GET "/api/poll?dev=$DEV" "${AUTH[@]}"
expect "2. poll while pending → {status:pending}" "$CODE $BODY" '200 {"status":"pending"}'
ROW=$(d1 "SELECT status, ts FROM devices WHERE id='$DEV'")
expect "2. devices row status pending" "$(jget "$ROW" 'j[0].status')" pending
# The untrusted heartbeat is throttled to once a minute now (the module's secret is self-issued,
# so a pending poll must not be a free D1 write on every hit). Within the window ts stays put; the
# card still shows "last seen" from the register a moment ago.
[ "$(jget "$ROW" 'j[0].ts')" = "$TS0" ] && pass "2. pending poll throttled (ts unchanged in-window)" || fail "2. pending poll should not have moved ts within the throttle window" "$ROW"
# A 1-char secret is not a credential: the module mints 32 hex from the TRNG, and the server floors
# it so a buggy/copycat firmware can't burn a guessable secret into a trusted device.
req POST "/api/register?dev=$(openssl rand -hex 8)" -H "Authorization: Bearer a" --data-binary "$BLOB"
expect "2. register with a too-short secret → 400" "$CODE" 400

# --- 3. web login, list, trust ------------------------------------------------------------
COOKIE=$(curl -s -o /dev/null -D - --data-urlencode "user=$WEB_USER" --data-urlencode "pass=$WEB_PASS" "$BASE/login" \
    | sed -n 's/^[Ss]et-[Cc]ookie: *sms_session=\([^;]*\).*/\1/p' | head -1)
[ -n "$COOKIE" ] && pass "3. login issued a session cookie" || fail "3. login gave no cookie"
WEB=(-H "Cookie: sms_session=$COOKIE")
req GET "/api/status" "${WEB[@]}"
expect "3. /api/status lists the device as pending" "$(jget "$BODY" "j.devices.find(d=>d.id==='$DEV').status")" pending
expect "3. /api/status marks it as a module" "$(jget "$BODY" "j.devices.find(d=>d.id==='$DEV').module")" 1
req POST "/api/device/trust" "${WEB[@]}" "${JSON[@]}" --data "{\"id\":\"$DEV\",\"status\":\"trusted\"}"
expect "3. trust → ok" "$CODE $BODY" '200 {"ok":true}'
req POST "/api/device/trust" "${WEB[@]}" "${JSON[@]}" --data "{\"id\":\"$DEV\",\"status\":\"root\"}"
expect "3. trust with a bad status → 400" "$CODE" 400
req POST "/api/device/trust" "${JSON[@]}" --data "{\"id\":\"$DEV\",\"status\":\"trusted\"}"
expect "3. trust without a session → 401" "$CODE" 401

# --- 4. trusted: poll, publish, claim + ack -------------------------------------------------
req GET "/api/poll?dev=$DEV" "${AUTH[@]}"
expect "4. poll trusted, nothing queued" "$CODE $BODY" '200 {"status":"trusted","rows":[],"cmd":null}'
req POST "/$TOPIC?dev=$DEV" "${AUTH[@]}" --data-binary "$BLOB"
expect "4. publish → 200 ok" "$CODE $BODY" "200 ok"
expect "4. messages row stored" "$(jget "$(d1 "SELECT count(*) AS n FROM messages WHERE body='$BLOB'")" 'j[0].n')" 1
d1 "INSERT INTO outbox (ts, payload, status, dev) VALUES ($(date +%s)000, 'v1:outbox-test', 'pending', '$DEV')" >/dev/null
req GET "/api/poll?dev=$DEV" "${AUTH[@]}"
expect "4. poll claims the outbox row" "$(jget "$BODY" 'j.rows.length + " " + j.rows[0].payload')" "1 v1:outbox-test"
OID=$(jget "$BODY" 'j.rows[0].id')
expect "4. claimed row is 'sending'" "$(jget "$(d1 "SELECT status, claims FROM outbox WHERE id=$OID")" 'j[0].status + " " + j[0].claims')" "sending 1"
req POST "/api/outbox/ack?dev=$DEV" "${AUTH[@]}" "${JSON[@]}" --data "{\"id\":$OID,\"ok\":true,\"detail\":\"SMS-test\"}"
expect "4. ack → ok" "$CODE $BODY" '200 {"ok":true}'
expect "4. acked row is 'sent'" "$(jget "$(d1 "SELECT status FROM outbox WHERE id=$OID")" 'j[0].status')" sent

# --- 4b. a module's ack is scoped to rows it could have claimed --------------------------------
DEV3=$(openssl rand -hex 8); SECRET3=$(openssl rand -hex 16); AUTH3=(-H "Authorization: Bearer $SECRET3")
req POST "/api/register?dev=$DEV3" "${AUTH3[@]}" --data-binary "$BLOB"
expect "4b. second module registers" "$CODE $BODY" '200 {"status":"pending"}'
req POST "/api/device/trust" "${WEB[@]}" "${JSON[@]}" --data "{\"id\":\"$DEV3\",\"status\":\"trusted\"}"
expect "4b. trust the second module" "$CODE" 200
# A send addressed to DEV3, already claimed by it.
d1 "INSERT INTO outbox (ts, payload, status, dev, claims) VALUES ($(date +%s)000, 'v1:for-dev3', 'sending', '$DEV3', 1)" >/dev/null
OID3=$(jget "$(d1 "SELECT id FROM outbox WHERE payload='v1:for-dev3'")" 'j[0].id')
# DEV (a different trusted module) tries to close DEV3's row — must not touch it.
req POST "/api/outbox/ack?dev=$DEV" "${AUTH[@]}" "${JSON[@]}" --data "{\"id\":$OID3,\"ok\":true,\"detail\":\"cross-device\"}"
expect "4b. cross-device ack still 200 (idempotent shape)" "$CODE $BODY" '200 {"ok":true}'
expect "4b. …but DEV3's row is untouched (scoped out)" "$(jget "$(d1 "SELECT status FROM outbox WHERE id=$OID3")" 'j[0].status')" sending
# The owner's phone (legacy token) is never scoped — it may close any row, exactly as before.
req POST "/api/outbox/ack?dev=phoneX" -H "Authorization: Bearer $SEND_TOKEN" "${JSON[@]}" --data "{\"id\":$OID3,\"ok\":true,\"detail\":\"phone-close\"}"
expect "4b. phone (legacy) may still close any row" "$(jget "$(d1 "SELECT status FROM outbox WHERE id=$OID3")" 'j[0].status')" sent
# DEV3 may of course close its own; prove the scoped path also permits the legitimate owner.
d1 "INSERT INTO outbox (ts, payload, status, dev, claims) VALUES ($(date +%s)000, 'v1:for-dev3b', 'sending', '$DEV3', 1)" >/dev/null
OID3B=$(jget "$(d1 "SELECT id FROM outbox WHERE payload='v1:for-dev3b'")" 'j[0].id')
req POST "/api/outbox/ack?dev=$DEV3" "${AUTH3[@]}" "${JSON[@]}" --data "{\"id\":$OID3B,\"ok\":true}"
expect "4b. a module may close its own row" "$(jget "$(d1 "SELECT status FROM outbox WHERE id=$OID3B")" 'j[0].status')" sent

# --- 5. commands ---------------------------------------------------------------------------
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"reboot\"}"
expect "5. queue reboot → ok" "$CODE $(jget "$BODY" 'j.ok')" "200 true"
CID=$(jget "$BODY" 'j.id')
req GET "/api/poll?dev=$DEV" "${AUTH[@]}"
expect "5. poll carries the cmd" "$(jget "$BODY" 'j.cmd.type + " " + j.cmd.id')" "reboot $CID"
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"reboot\"}"
expect "5. second cmd while one pending → 409" "$CODE $BODY" '409 {"error":"pending"}'
req POST "/api/cmd/ack?dev=$DEV" "${AUTH[@]}" "${JSON[@]}" --data "{\"id\":$CID,\"ok\":true,\"detail\":\"rebooting\"}"
expect "5. cmd ack → ok" "$CODE $BODY" '200 {"ok":true}'
req GET "/api/cmd/list?dev=$DEV" "${WEB[@]}"
expect "5. list shows done + detail" "$(jget "$BODY" 'j[0].status + " " + j[0].detail')" "done rebooting"
req DELETE "/api/cmd/$CID" "${WEB[@]}"
expect "5. DELETE of a done cmd is a no-op" "$CODE $(jget "$BODY" 'j.deleted')" "200 0"
req GET "/api/cmd/list?dev=$DEV" "${WEB[@]}"
expect "5. done cmd still listed" "$(jget "$BODY" 'j.length')" 1
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"reboot\"}"
CID2=$(jget "$BODY" 'j.id')
req DELETE "/api/cmd/$CID2" "${WEB[@]}"
expect "5. DELETE of a pending cmd removes it" "$CODE $(jget "$BODY" 'j.deleted')" "200 1"
# `bases` is the one command that can take a module away for good — it moves the module to
# another server, after which 拉黑/忘记 never reach it again. So the browser signs it with
# SMS_KEY exactly the way it signs an "ota", and this server (which never holds the key) can
# neither verify nor forge the MAC: all it does is insist a well-formed one is present and
# carry it through to the module, which checks it against the value as stored. A 64-hex string
# is therefore all this test can assert on — only the module can tell a good MAC from a bad one.
BHMAC=$(printf 'ab%.0s' {1..32})
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"bases\",\"value\":\"https://ok.example\"}"
expect "5. bases with no hmac → 400" "$CODE" 400
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"bases\",\"value\":\"https://ok.example\",\"hmac\":\"abcd1234\"}"
expect "5. bases with a short hmac → 400" "$CODE" 400
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"bases\",\"value\":\"https://ok.example\",\"hmac\":\"${BHMAC}ab\"}"
expect "5. bases with an over-long hmac → 400" "$CODE" 400
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"bases\",\"value\":\"https://ok.example\",\"hmac\":\"$(printf 'zz%.0s' {1..32})\"}"
expect "5. bases with a non-hex hmac → 400" "$CODE" 400
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"bases\",\"value\":\"http://plain.example\",\"hmac\":\"$BHMAC\"}"
expect "5. bases with a non-https url → 400" "$CODE" 400
# A query string / fragment / quote in a base would ride along when the module appends "/api/…",
# bricking it — validate hard and reject, don't store.
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"bases\",\"value\":\"https://h.example/?a=1#f\",\"hmac\":\"$BHMAC\"}"
expect "5. bases with a query/fragment → 400" "$CODE" 400
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"bases\",\"value\":\"https://h.example/a/b/\",\"hmac\":\"$BHMAC\"}"
expect "5. bases with a trailing slash → 200" "$CODE" 200
CIDTS=$(jget "$BODY" 'j.id')
req GET "/api/poll?dev=$DEV" "${AUTH[@]}"
expect "5. trailing slash dropped on the way in" "$(jget "$BODY" 'j.cmd.value')" "https://h.example/a/b"
req POST "/api/cmd/ack?dev=$DEV" "${AUTH[@]}" "${JSON[@]}" --data "{\"id\":$CIDTS,\"ok\":true}"
# A malformed percent-escape in the cmd id path must not throw an unhandled 500.
req DELETE "/api/cmd/%" "${WEB[@]}"
expect "5. DELETE /api/cmd/% → 400 (not a 500)" "$CODE" 400
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"bases\",\"value\":\" https://a.example , https://b.example:8443/x \",\"hmac\":\"$(printf 'AB%.0s' {1..32})\"}"
expect "5. bases with a valid list → ok" "$CODE" 200
CID3=$(jget "$BODY" 'j.id')
req GET "/api/poll?dev=$DEV" "${AUTH[@]}"
expect "5. bases list arrives normalised" "$(jget "$BODY" 'j.cmd.value')" "https://a.example,https://b.example:8443/x"
# The module verifies the MAC over the value exactly as stored, so the poll has to carry it
# through untouched (lowercased, like an "ota" signature).
expect "5. poll carries the bases hmac (lowercased)" "$(jget "$BODY" 'j.cmd.hmac')" "$BHMAC"
req POST "/api/cmd/ack?dev=$DEV" "${AUTH[@]}" "${JSON[@]}" --data "{\"id\":$CID3,\"ok\":false,\"detail\":\"no such host\"}"
req GET "/api/cmd/list?dev=$DEV" "${WEB[@]}"
expect "5. failed ack recorded" "$(jget "$BODY" 'j[0].status + " " + j[0].detail')" "failed no such host"
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"phone-no-such\",\"type\":\"reboot\"}"
expect "5. cmd for an unknown/phone dev → 404" "$CODE" 404

# --- 6. OTA --------------------------------------------------------------------------------
printf -- '-- test script\nlocal M = {}\nreturn M\n' > "$TMP/gw.lua"
req POST "/api/ota/put?name=gw" "${WEB[@]}" --data-binary "@$TMP/gw.lua"
expect "6. ota put → ok" "$CODE $(jget "$BODY" 'j.ok')" "200 true"
expect "6. ota put size" "$(jget "$BODY" 'j.size')" "$(wc -c < "$TMP/gw.lua" | tr -d ' ')"
SHA=$(shasum -a 256 "$TMP/gw.lua" | cut -d' ' -f1)
expect "6. ota put sha256 matches shasum" "$(jget "$BODY" 'j.sha256')" "$SHA"
req GET "/api/ota/meta" "${WEB[@]}"
expect "6. ota meta gw" "$(jget "$BODY" 'j.gw.sha256 + " " + j.gw.size + " " + (j.gw.ts > 0)')" "$SHA $(wc -c < "$TMP/gw.lua" | tr -d ' ') true"
expect "6. ota meta gcm empty" "$(jget "$BODY" 'j.gcm')" null
GCODE=$(curl -s "$BASE/api/ota/get?dev=$DEV&name=gw" "${AUTH[@]}" -o "$TMP/got.lua" -w '%{http_code}')
expect "6. ota get → 200" "$GCODE" 200
cmp -s "$TMP/gw.lua" "$TMP/got.lua" && pass "6. ota get bytes identical" || fail "6. ota get bytes differ"
DEV2=$(openssl rand -hex 8); SECRET2=$(openssl rand -hex 16)
req POST "/api/register?dev=$DEV2" -H "Authorization: Bearer $SECRET2" --data-binary "$BLOB"
expect "6. second (pending) device registers" "$CODE $BODY" '200 {"status":"pending"}'
req GET "/api/ota/get?dev=$DEV2&name=gw" -H "Authorization: Bearer $SECRET2"
expect "6. ota get by a pending device → 403" "$CODE $BODY" "403 forbidden"
req GET "/api/ota/get?dev=$DEV&name=zzz" "${AUTH[@]}"
case "$CODE" in 400|404) pass "6. ota get unknown name → $CODE" ;; *) fail "6. ota get unknown name" "$CODE $BODY" ;; esac
req GET "/api/ota/get?dev=$DEV&name=gcm" "${AUTH[@]}"
expect "6. ota get never-uploaded name → 404" "$CODE" 404
printf 'PK\003\004 definitely not lua' > "$TMP/junk.bin"
req POST "/api/ota/put?name=gw" "${WEB[@]}" --data-binary "@$TMP/junk.bin"
expect "6. ota put of a non-Lua file → 400" "$CODE" 400
head -c 200001 /dev/zero | tr '\0' 'x' > "$TMP/big.lua"
req POST "/api/ota/put?name=gw" "${WEB[@]}" --data-binary "@$TMP/big.lua"
expect "6. ota put over 200000 bytes → 413" "$CODE" 413
HMAC=$(openssl dgst -sha256 -mac HMAC -macopt hexkey:"$(openssl rand -hex 32)" "$TMP/gw.lua" | sed 's/.*= *//')
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"ota\",\"name\":\"gw\",\"hmac\":\"$HMAC\"}"
expect "6. ota cmd → ok" "$CODE" 200
CID4=$(jget "$BODY" 'j.id')
req GET "/api/poll?dev=$DEV" "${AUTH[@]}"
expect "6. poll carries ota cmd with name + hmac" "$(jget "$BODY" 'j.cmd.type + " " + j.cmd.name + " " + j.cmd.hmac')" "ota gw $HMAC"
req POST "/api/cmd/ack?dev=$DEV" "${AUTH[@]}" "${JSON[@]}" --data "{\"id\":$CID4,\"ok\":true,\"detail\":\"$(wc -c < "$TMP/gw.lua" | tr -d ' ') bytes\"}"
req POST "/api/cmd" "${WEB[@]}" "${JSON[@]}" --data "{\"dev\":\"$DEV\",\"type\":\"ota\",\"name\":\"gw\",\"hmac\":\"short\"}"
expect "6. ota cmd with a bad hmac → 400" "$CODE" 400

# --- 7. block ------------------------------------------------------------------------------
req POST "/api/device/trust" "${WEB[@]}" "${JSON[@]}" --data "{\"id\":\"$DEV\",\"status\":\"blocked\"}"
expect "7. block → ok" "$CODE" 200
req POST "/$TOPIC?dev=$DEV" "${AUTH[@]}" --data-binary "$BLOB"
expect "7. publish while blocked → 403" "$CODE $BODY" "403 forbidden"
req GET "/api/poll?dev=$DEV" "${AUTH[@]}"
expect "7. poll while blocked → {status:blocked}" "$CODE $BODY" '200 {"status":"blocked"}'
req POST "/api/cmd/ack?dev=$DEV" "${AUTH[@]}" "${JSON[@]}" --data "{\"id\":$CID4,\"ok\":true}"
expect "7. cmd ack while blocked → 403" "$CODE" 403

# --- 8. legacy phone path (SEND_TOKEN) must be untouched ------------------------------------
LEG=(-H "Authorization: Bearer $SEND_TOKEN")
req POST "/$TOPIC?dev=phone1" "${LEG[@]}" --data-binary "$BLOB"
expect "8. phone publish → 200 ok" "$CODE $BODY" "200 ok"
req GET "/api/outbox?dev=phone1" "${LEG[@]}"
expect "8. phone /api/outbox → 200 []" "$CODE $BODY" "200 []"
req POST "/api/devinfo?dev=phone1" "${LEG[@]}" --data-binary "$BLOB"
expect "8. phone devinfo → ok" "$CODE $BODY" '200 {"ok":true}'
req POST "/api/devinfo" "${LEG[@]}" --data-binary "$BLOB"
expect "8. phone devinfo without dev → 400" "$CODE $BODY" '400 {"error":"bad"}'
req POST "/api/outbox/ack" "${LEG[@]}" "${JSON[@]}" --data '{"id":999999,"ok":true,"detail":"x"}'
expect "8. phone ack → ok" "$CODE $BODY" '200 {"ok":true}'
req GET "/api/deletions?since=0" "${LEG[@]}"
expect "8. phone deletions → 200 []" "$CODE $BODY" "200 []"
req GET "/api/app?meta=1" "${LEG[@]}"
expect "8. phone app meta → 200" "$CODE" 200
ROW=$(d1 "SELECT auth, status FROM devices WHERE id='phone1'")
expect "8. phone row: auth NULL, status trusted" "$(jget "$ROW" 'String(j[0].auth) + " " + j[0].status')" "null trusted"
req GET "/api/poll?dev=phone1" "${LEG[@]}"
expect "8. /api/poll with the legacy token → 403" "$CODE $BODY" "403 forbidden"
req GET "/api/outbox?dev=phone1" -H "Authorization: Bearer nope"
expect "8. wrong token on /api/outbox → 403 forbidden (text)" "$CODE $BODY" "403 forbidden"
req POST "/$TOPIC?dev=phone1" -H "Authorization: Bearer nope" --data-binary "$BLOB"
expect "8. wrong token on publish → 403 forbidden (text)" "$CODE $BODY" "403 forbidden"
req POST "/wrong-topic" -H "Authorization: Bearer nope" --data-binary "$BLOB"
expect "8. wrong topic beats wrong token → 404" "$CODE $BODY" "404 unknown topic"
req POST "/$TOPIC?dev=phone1" "${LEG[@]}"
expect "8. empty body → 400" "$CODE $BODY" "400 empty body"
req GET "/api/deletions?since=0" -H "Authorization: Bearer nope"
expect "8. wrong token on deletions → 401 JSON" "$CODE $BODY" '401 {"error":"unauthorized"}'
req GET "/api/app?meta=1" -H "Authorization: Bearer nope"
expect "8. wrong token on app → 401 JSON" "$CODE $BODY" '401 {"error":"unauthorized"}'
# A phone id that also passes the module id rule (Android uses 16 lowercase hex too): a module
# must not be able to take it over by registering under it.
PHONE=$(openssl rand -hex 8)
req GET "/api/outbox?dev=$PHONE" "${LEG[@]}"
expect "8. hex-id phone polls → 200 []" "$CODE $BODY" "200 []"
req POST "/api/register?dev=$PHONE" "${AUTH[@]}" --data-binary "$BLOB"
expect "8. module registering under a phone's id → 409" "$CODE" 409

# --- 9. forget, then register again ---------------------------------------------------------
req POST "/api/device/forget" "${WEB[@]}" "${JSON[@]}" --data "{\"id\":\"$DEV\"}"
expect "9. forget → ok" "$CODE $BODY" '200 {"ok":true}'
expect "9. devices row gone" "$(jget "$(d1 "SELECT count(*) AS n FROM devices WHERE id='$DEV'")" 'j[0].n')" 0
req POST "/api/register?dev=$DEV" "${AUTH[@]}" --data-binary "$BLOB"
expect "9. register again → pending again" "$CODE $BODY" '200 {"status":"pending"}'

# --- page sanity ---------------------------------------------------------------------------
PAGE=$(curl -s "$BASE/" "${WEB[@]}")
for w in "待信任" "更新脚本" "已拉黑" "重启计数" 'id="otaFile"'; do
    # Here-string, not a pipe: grep -q exits on the first match, and under pipefail the SIGPIPE
    # that gives echo would turn a successful match into a failure.
    grep -q -- "$w" <<<"$PAGE" && pass "page contains $w" || fail "page lacks $w"
done

echo
echo "all green"
