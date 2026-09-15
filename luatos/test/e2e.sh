#!/usr/bin/env bash
# e2e.sh — end-to-end test of the Air780EHV module against the LOCAL wrangler
# dev server (http://127.0.0.1:8787) and its local D1/KV. Boots the real main.lua
# (which loads the real gw.lua) through fake_luatos.lua with real curl HTTP, plays
# the web side with curl (login cookie, 信任/拉黑, commands, the OTA upload) and
# inspects D1 + decrypts the stored ciphertext with Node (same AES-256-GCM key)
# to prove byte-for-byte protocol compatibility with the Worker.
#
# The device is provisioned the way a real one is: a throwaway config.lua with a
# fresh random SMS_KEY (+ BASES/TOPIC for the local server). It registers itself,
# shows up pending, gets trusted here. SMS commands need no configuration at all —
# they are signed with that same SMS_KEY (see smsmac below and luatos/sms-sign.sh).
#
# Secrets: TOPIC is read from worker/wrangler.toml and WEB_USER/WEB_PASS from
# worker/.dev.vars AT RUNTIME — never written into a repo file, never echoed. The
# test config.lua lives in a throwaway temp dir (never the repo).
#
# Prereqs: the local dev server must be up (npx wrangler dev --port 8787 --local
# in worker/) with schema.sql + the two ALTERs applied. lua 5.4, node, openssl,
# curl on PATH. Never touches --remote.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKER="$REPO/worker"
BASE="http://127.0.0.1:8787"

# Throwaway workspace (config.lua + fskv snapshots + OTA sandbox + node helpers).
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sms-e2e.XXXXXX")"
mkdir -p "$WORK/gcm" "$WORK/fs"      # fs/ = the fake's writable-FS sandbox (/ota_*.lua)

BODY='验证码 987654，请勿泄露。'   # inbound SMS text (Chinese), asserted verbatim
SMS_FROM="+8613800138000"       # any number: an SMS command is authenticated by its mac

pass() { printf '✅ %s\n' "$1"; }
fail() { printf '❌ %s\n' "$1" >&2; [ $# -gt 1 ] && printf '   %s\n' "$2" >&2; exit 1; }

# ---- probe the dev server ---------------------------------------------------
code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/status" || true)"
[ "$code" = "401" ] || fail "local wrangler dev not reachable at $BASE (/api/status returned '$code', want 401)" \
  "start it: cd worker && npx wrangler dev --port 8787 --local"
code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/poll?dev=x" || true)"
[ "$code" = "403" ] || fail "dev server is not running the device-registry Worker (/api/poll returned '$code', want 403)"
pass "local wrangler dev is up ($BASE) and serves the device routes"

# ---- read config at runtime (never persisted to the repo) -------------------
TOPIC="$(grep -E '^[[:space:]]*TOPIC[[:space:]]*=' "$WORKER/wrangler.toml" | head -1 | sed -E 's/.*"([^"]*)".*/\1/')"
val() { sed -n "s/^$1=//p" "$WORKER/.dev.vars" | head -1 | tr -d '\r"'; }
WEB_USER="$(val WEB_USER)"; WEB_PASS="$(val WEB_PASS)"
[ -n "$TOPIC" ] || fail "could not read TOPIC from wrangler.toml"
[ -n "$WEB_USER" ] && [ -n "$WEB_PASS" ] || fail "could not read WEB_USER/WEB_PASS from .dev.vars"
KEY="$(openssl rand -hex 32)"
pass "read TOPIC + web credentials at runtime, generated fresh SMS_KEY"

# ---- node helpers (same key as the module) ----------------------------------
cat > "$WORK/enc.js" <<'JS'
const crypto = require("crypto");
const key = Buffer.from(process.env.K, "hex");
function enc(pt){
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(pt, "utf8")), c.final()]);
  return "v1:" + Buffer.concat([iv, ct, c.getAuthTag()]).toString("base64");
}
const cmd = process.argv[2];
if (cmd === "enc") process.stdout.write(enc(process.argv[3]));
else if (cmd === "badtag") {                 // valid v1 with one tag byte flipped
  const r = Buffer.from(enc(process.argv[3]).slice(3), "base64");
  r[r.length - 1] ^= 0xff;
  process.stdout.write("v1:" + r.toString("base64"));
}
JS
# dec.js: decrypt results[].<field> from a `wrangler d1 execute --json` dump.
cat > "$WORK/dec.js" <<'JS'
const crypto = require("crypto");
const key = Buffer.from(process.env.K, "hex");
function dec(v1){
  const r = Buffer.from(v1.slice(3), "base64");
  const iv = r.subarray(0, 12), tag = r.subarray(r.length - 16), ct = r.subarray(12, r.length - 16);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}
let s = ""; process.stdin.on("data", d => s += d); process.stdin.on("end", () => {
  const rows = JSON.parse(s)[0].results, f = process.argv[2];
  for (const row of rows) { try { console.log(dec(row[f])); } catch (e) { console.log("DECRYPT_ERROR:" + e.message); } }
});
JS
# jget.js: scalar results[0][field]; jcol.js: every results[].field, one per line.
cat > "$WORK/jget.js" <<'JS'
let s=""; process.stdin.on("data",d=>s+=d); process.stdin.on("end",()=>{
  const r=JSON.parse(s)[0].results; process.stdout.write(r.length?String(r[0][process.argv[2]]):"");
});
JS
cat > "$WORK/jcol.js" <<'JS'
let s=""; process.stdin.on("data",d=>s+=d); process.stdin.on("end",()=>{
  for(const row of JSON.parse(s)[0].results) console.log(row[process.argv[2]]);
});
JS
# jj.js: evaluate a JS expression over a JSON document on stdin (web API responses).
cat > "$WORK/jj.js" <<'JS'
let s=""; process.stdin.on("data",d=>s+=d); process.stdin.on("end",()=>{
  const j=JSON.parse(s); const v=eval(process.argv[2]); process.stdout.write(typeof v==="string"?v:JSON.stringify(v));
});
JS
# kvget.js: a value from the fake's fskv file ("<b64 key>\t<type>\t<b64 payload>" per line).
cat > "$WORK/kvget.js" <<'JS'
const fs=require("fs"); const want=process.argv[3];
for (const l of fs.readFileSync(process.argv[2],"utf8").split("\n")) {
  if (!l) continue; const [k,,v]=l.split("\t");
  if (Buffer.from(k,"base64").toString()===want) { process.stdout.write(Buffer.from(v,"base64").toString()); process.exit(0); }
}
JS

enc()   { K="$KEY" node "$WORK/enc.js" enc "$1"; }
badtag(){ K="$KEY" node "$WORK/enc.js" badtag "$1"; }
jj()    { printf '%s' "$1" | node "$WORK/jj.js" "$2"; }
kvget() { node "$WORK/kvget.js" "$1" "$2"; }

# ---- D1 helpers (local only, from worker/) ----------------------------------
d1()     { ( cd "$WORKER" && npx wrangler d1 execute sms --local --command "$1" >/dev/null 2>&1 ); }
d1json() { ( cd "$WORKER" && npx wrangler d1 execute sms --local --json --command "$1" 2>/dev/null ); }
kvdel()  { ( cd "$WORKER" && npx wrangler kv key delete --binding APK --local "$1" >/dev/null 2>&1 || true ); }

# ---- web side: login cookie, trust, commands, OTA upload ----------------------
COOKIE="$(curl -s -o /dev/null -D - --data-urlencode "user=$WEB_USER" --data-urlencode "pass=$WEB_PASS" "$BASE/login" \
  | sed -n 's/^[Ss]et-[Cc]ookie: *sms_session=\([^;]*\).*/\1/p' | head -1)"
[ -n "$COOKIE" ] || fail "web login gave no session cookie"
pass "web login issued a session cookie"
web()   { curl -s -H "Cookie: sms_session=$COOKIE" "$@"; }
trust() { web -X POST "$BASE/api/device/trust" -H 'Content-Type: application/json' --data "{\"id\":\"$1\",\"status\":\"$2\"}" >/dev/null; }
cmd_queue() { # json fields after dev → prints the cmd id
  local r; r="$(web -X POST "$BASE/api/cmd" -H 'Content-Type: application/json' --data "{\"dev\":\"$1\",$2}")"
  jj "$r" 'j.id' || fail "queueing cmd failed" "$r"
}
cmd_row() { # id → "<status>|<detail>"
  local r; r="$(web "$BASE/api/cmd/list?dev=$1")"
  jj "$r" "(j.find(c=>c.id===$2)||{}).status + '|' + (j.find(c=>c.id===$2)||{}).detail"
}
dev_status() { jj "$(web "$BASE/api/status")" "(j.devices.find(d=>d.id==='$1')||{}).status + '|' + (j.devices.find(d=>d.id==='$1')||{}).module"; }

# ---- test config.lua files (normal / wrong-topic / dead-base) ----------------
write_config() { # dir topic bases
  mkdir -p "$1"
  cat > "$1/config.lua" <<EOF
return {
  SMS_KEY = "$KEY",
  BASES = { $3 },
  TOPIC = "$2",
}
EOF
}
write_config "$WORK/conf"      "$TOPIC"          '"'"$BASE"'"'
write_config "$WORK/conf_wt"   "wrong-topic-xyz" '"'"$BASE"'"'
write_config "$WORK/conf_dead" "$TOPIC"          '"http://127.0.0.1:9"'
FSKV="$WORK/fskv.dat"

run_driver() { # confdir fskv [VAR=value …] → the driver's KEY=VALUE output
  local conf="$1" fskv="$2"; shift 2
  env "$@" E2E_CONFDIR="$conf" E2E_FSKV="$fskv" GCM_SCRATCH="$WORK/gcm" FAKE_FS_ROOT="$WORK/fs" \
    lua "$REPO/luatos/test/e2e_driver.lua"
}
kv() { printf '%s\n' "$1" | grep -E "^$2=" | head -1 | sed -E "s/^$2=//"; }

# ---- park any pre-existing claimable rows so they can't be grabbed ----------
d1 "UPDATE outbox SET status='e2e_hold' WHERE status IN ('pending','sending');"
restore_parked() { d1 "UPDATE outbox SET status='pending' WHERE status='e2e_hold';"; }

CREATED_MSGS=""; CREATED_OUT=""; CREATED_DEV=""
cleanup() {
  for id in $CREATED_OUT;  do d1 "DELETE FROM outbox   WHERE id=$id;"; done
  for id in $CREATED_MSGS; do d1 "DELETE FROM messages WHERE id=$id;"; done
  for id in $CREATED_DEV;  do d1 "DELETE FROM cmds WHERE dev='$id';"; d1 "DELETE FROM devices WHERE id='$id';"; done
  kvdel "ota:gw"; kvdel "ota:gw:meta"
  restore_parked
  rm -rf "$WORK"
}
trap cleanup EXIT

# =============================================================================
# 0. First boot: the module registers itself and waits, pending, on the web
# =============================================================================
OUT="$(run_driver "$WORK/conf" "$FSKV")"
DEV="$(kv "$OUT" DEVID)"
[ -n "$DEV" ] || fail "driver did not report a DEVID" "$OUT"
CREATED_DEV="$DEV"
[ "$(kv "$OUT" REGS)" -ge 1 ] || fail "module did not register" "$OUT"
[ "$(kv "$OUT" TRUST)" = "pending" ] || fail "module should see itself pending" "$OUT"
[ "$(kv "$OUT" BOOT_FAIL)" = "0" ] || fail "pending polls are answered → alive → boot_fail must clear after 5 min" "$OUT"
[ "$(d1json "SELECT status FROM devices WHERE id='$DEV';" | node "$WORK/jget.js" status)" = "pending" ] || fail "D1 row not pending"
pass "first boot: registered (dev=$DEV), D1 row pending, module polls and sees 'pending'; boot_fail cleared by answered polls"
EXP_REG='{"n":"Air780EHV","s":[{"slot":0,"name":"SIM 1 · 中国电信"}],"t":"4G","os":"LuatOS V2050 Air780EHV","v":"2.0.0","ls":"","imei":"861234567890123","iccid":"89860012345678901234","imsi":"460110123456789","num":"","fw":"V2050","ver":"2.0.0","ota":"-","boot":1}'
DINFO="$(d1json "SELECT info FROM devices WHERE id='$DEV';" | K="$KEY" node "$WORK/dec.js" info)"
[ "$DINFO" = "$EXP_REG" ] || fail "register blob mismatch" "want: $EXP_REG"$'\n'"got:  $DINFO"
pass "register blob decrypts to the exact self-description (imei/iccid/imsi/num/fw/ver/ota/boot present)"
[ "$(dev_status "$DEV")" = "pending|1" ] || fail "/api/status should list the module as pending" "$(dev_status "$DEV")"
pass "/api/status lists it as a pending module"

# =============================================================================
# 1. Trust on the web → the next poll says trusted → the module re-registers
# =============================================================================
trust "$DEV" trusted
OUT="$(run_driver "$WORK/conf" "$FSKV")"
[ "$(kv "$OUT" TRUST)" = "trusted" ] || fail "module should see itself trusted" "$OUT"
[ "$(kv "$OUT" REGS)" -ge 1 ] || fail "no register on this boot" "$OUT"
pass "trusted on the web: poll reports trusted"

# =============================================================================
# 2. Inbound: one SMS (10001) + one missed call (+8613800138000) → messages
# =============================================================================
OUT="$(run_driver "$WORK/conf" "$FSKV" E2E_SMS_TEXT="$BODY" E2E_CALL=1)"
[ "$(kv "$OUT" QUEUE)" = "0" ] || fail "inbound queue not drained" "$OUT"
pass "inbound run drained its queue"
MSGS_JSON="$(d1json "SELECT id, body FROM messages ORDER BY id DESC LIMIT 2;")"
CREATED_MSGS="$(printf '%s' "$MSGS_JSON" | node "$WORK/jcol.js" id | tr '\n' ' ')"
DEC="$(printf '%s' "$MSGS_JSON" | K="$KEY" node "$WORK/dec.js" body)"
EXP_SMS='{"s":"10001","b":"'"$BODY"'","k":"SIM 1 · 中国电信","d":"'"$DEV"'"}'
EXP_CALL='{"s":"+8613800138000","b":"未接来电","k":"SIM 1 · 中国电信","d":"'"$DEV"'"}'
printf '%s\n' "$DEC" | grep -Fxq "$EXP_SMS"  || fail "inbound SMS row mismatch" "want: $EXP_SMS"$'\n'"got:  $DEC"
pass "inbound SMS decrypts to exact JSON: $EXP_SMS"
printf '%s\n' "$DEC" | grep -Fxq "$EXP_CALL" || fail "missed-call row mismatch" "want: $EXP_CALL"$'\n'"got:  $DEC"
pass "missed call decrypts to exact JSON: $EXP_CALL"

# =============================================================================
# 3. Outbox: insert a pending row for this dev → poll → send + ack sent
# =============================================================================
PAYLOAD="$(enc '{"to":"10086","body":"YE","sim":""}')"
d1 "INSERT INTO outbox (ts,payload,status,dev,claims) VALUES ($(date +%s)000,'$PAYLOAD','pending','$DEV',0);"
RID="$(d1json "SELECT id FROM outbox WHERE dev='$DEV' ORDER BY id DESC LIMIT 1;" | node "$WORK/jget.js" id)"
CREATED_OUT="$RID"
OUT="$(run_driver "$WORK/conf" "$FSKV")"
[ "$(kv "$OUT" SENT)" = "1" ] || fail "expected exactly one send" "$OUT"
SLINE="$(printf '%s\n' "$OUT" | grep '^SEND	' | head -1)"
[ "$SLINE" = "$(printf 'SEND\t10086\tYE')" ] || fail "sms.send to/body wrong" "$SLINE"
pass "poll sent SMS to 10086 body 'YE'"
STATUS="$(d1json "SELECT status FROM outbox WHERE id=$RID;" | node "$WORK/jget.js" status)"
DETAIL="$(d1json "SELECT detail FROM outbox WHERE id=$RID;" | node "$WORK/jget.js" detail)"
[ "$STATUS" = "sent" ] || fail "outbox row not marked sent" "status=$STATUS"
printf '%s' "$DETAIL" | grep -Eq '^SMS-[0-9]{8}-[0-9a-f]{8}$' || fail "ack detail not an attempt id" "detail=$DETAIL"
pass "outbox row status=sent, detail=$DETAIL"

# =============================================================================
# 4. Replay: flip the row back to pending → poll → NO re-send, replay detail
# =============================================================================
d1 "UPDATE outbox SET status='pending', claims=0 WHERE id=$RID;"
OUT="$(run_driver "$WORK/conf" "$FSKV")"
[ "$(kv "$OUT" SENT)" = "0" ] || fail "re-served row was re-sent (should replay)" "$OUT"
DETAIL="$(d1json "SELECT detail FROM outbox WHERE id=$RID;" | node "$WORK/jget.js" detail)"
[ "$DETAIL" = "此前已处理，重发请求已忽略" ] || fail "replay detail wrong" "detail=$DETAIL"
pass "re-served row not re-sent; detail='此前已处理，重发请求已忽略'"

# =============================================================================
# 5. Bad tag: corrupted ciphertext → acked failed, OUTBOX_DECRYPT_FAILED
# =============================================================================
BADPAY="$(badtag '{"to":"10086","body":"nope","sim":""}')"
d1 "INSERT INTO outbox (ts,payload,status,dev,claims) VALUES ($(date +%s)000,'$BADPAY','pending','$DEV',0);"
BID="$(d1json "SELECT id FROM outbox WHERE dev='$DEV' ORDER BY id DESC LIMIT 1;" | node "$WORK/jget.js" id)"
CREATED_OUT="$CREATED_OUT $BID"
OUT="$(run_driver "$WORK/conf" "$FSKV")"
[ "$(kv "$OUT" SENT)" = "0" ] || fail "bad-tag row must not send" "$OUT"
STATUS="$(d1json "SELECT status FROM outbox WHERE id=$BID;" | node "$WORK/jget.js" status)"
DETAIL="$(d1json "SELECT detail FROM outbox WHERE id=$BID;" | node "$WORK/jget.js" detail)"
[ "$STATUS" = "failed" ] || fail "bad-tag row not marked failed" "status=$STATUS"
case "$DETAIL" in
  OUTBOX_DECRYPT_FAILED｜*) : ;;
  *) fail "bad-tag detail prefix wrong" "detail=$DETAIL" ;;
esac
pass "bad-tag row status=failed, detail starts 'OUTBOX_DECRYPT_FAILED｜'"

# =============================================================================
# 6. Wrong topic: a second module, trusted, publishes → 404 → dropped permanently
# =============================================================================
OUT="$(run_driver "$WORK/conf_wt" "$WORK/fskv_wt.dat")"
WTDEV="$(kv "$OUT" DEVID)"
CREATED_DEV="$CREATED_DEV $WTDEV"
[ "$(kv "$OUT" TRUST)" = "pending" ] || fail "wrong-topic device should register pending" "$OUT"
trust "$WTDEV" trusted
MSGS_BEFORE="$(d1json "SELECT count(*) c FROM messages;" | node "$WORK/jget.js" c)"
OUT="$(run_driver "$WORK/conf_wt" "$WORK/fskv_wt.dat" E2E_SMS_TEXT="wrong topic" E2E_CALL=1)"
[ "$(kv "$OUT" TRUST)" = "trusted" ] || fail "wrong-topic device not trusted" "$OUT"
[ "$(kv "$OUT" QUEUE)" = "0" ] || fail "wrong-topic message not dropped (still queued)" "$OUT"
MSGS_AFTER="$(d1json "SELECT count(*) c FROM messages;" | node "$WORK/jget.js" c)"
[ "$MSGS_AFTER" = "$MSGS_BEFORE" ] || fail "wrong-topic message reached D1" "before=$MSGS_BEFORE after=$MSGS_AFTER"
pass "wrong-topic (404) dropped both messages, none written to D1, queue empty"

# =============================================================================
# 7. Dead base: nothing answers → never trusted, message stays queued in fskv
# =============================================================================
OUT="$(run_driver "$WORK/conf_dead" "$WORK/fskv_dead.dat" E2E_SMS_TEXT="unreachable base test")"
[ "$(kv "$OUT" TRUST)" = "?" ] || fail "dead-base device must never learn a trust status" "$OUT"
[ "$(kv "$OUT" QUEUE)" -ge 1 ] || fail "dead-base message should stay queued" "$OUT"
[ "$(kv "$OUT" TRIES)" = "0" ] || fail "an untrusted module must not even try to upload" "$OUT"
[ "$(kv "$OUT" POLL_FAIL)" -ge 2 ] || fail "dead-base polls should be failing (>=2)" "$OUT"
[ "$(kv "$OUT" BOOT_FAIL)" = "1" ] || fail "never alive → boot_fail must not clear" "$OUT"
[ -n "$(kvget "$WORK/fskv_dead.dat" "q:$(kv "$OUT" QSEQ)")" ] || fail "dead-base message not persisted in fskv (no q: key)"
pass "dead-base message stayed queued ($(kv "$OUT" POLL_FAIL) failed polls, 0 uploads) and persisted in fskv; boot_fail not cleared"

# =============================================================================
# 8. Web reboot command → acked before the reboot, cmds row done
# =============================================================================
CID="$(cmd_queue "$DEV" '"type":"reboot"')"
OUT="$(run_driver "$WORK/conf" "$FSKV")"
[ "$(kv "$OUT" REBOOTED)" = "true" ] || fail "module did not reboot on the reboot cmd" "$OUT"
[ "$(kv "$OUT" LAST_ACK)" = "{\"id\":$CID,\"ok\":true,\"detail\":\"rebooting\"}" ] || fail "reboot ack body wrong" "$OUT"
[ "$(kv "$OUT" LAST_CMD)" = "$CID" ] || fail "last_cmd not persisted" "$OUT"
[ "$(kv "$OUT" BOOT_FAIL)" = "0" ] || fail "a deliberate reboot must clear boot_fail" "$OUT"
[ "$(cmd_row "$DEV" "$CID")" = "done|rebooting" ] || fail "cmds row not done" "$(cmd_row "$DEV" "$CID")"
pass "web reboot cmd #$CID: acked 'rebooting' (cmds row done), boot_fail cleared, module rebooted"

# =============================================================================
# 9. Web OTA: upload a modified gw.lua via /api/ota/put, HMAC over "gw\n"+bytes
#    (openssl, test key), queue the ota cmd → module installs, acks, reboots →
#    OTA copy active on the next boot and still polling
# =============================================================================
tail -1 "$REPO/luatos/gw.lua" | grep -q '^return M$' || fail "gw.lua must end with 'return M'"
{ sed '$d' "$REPO/luatos/gw.lua"; printf '_G.GW_TAG = "ota"\nreturn M\n'; } > "$WORK/gw.lua"
HMAC="$({ printf 'gw\n'; cat "$WORK/gw.lua"; } | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$KEY" -r | cut -d' ' -f1)"
PUT="$(web -X POST "$BASE/api/ota/put?name=gw" --data-binary "@$WORK/gw.lua")"
[ "$(jj "$PUT" 'j.ok')" = "true" ] || fail "ota put failed" "$PUT"
[ "$(jj "$PUT" 'j.size')" = "$(wc -c < "$WORK/gw.lua" | tr -d ' ')" ] || fail "ota put size mismatch" "$PUT"
CID="$(cmd_queue "$DEV" "\"type\":\"ota\",\"name\":\"gw\",\"hmac\":\"$HMAC\"")"
OUT="$(run_driver "$WORK/conf" "$FSKV")"
[ "$(kv "$OUT" LAST_ACK)" = "{\"id\":$CID,\"ok\":true,\"detail\":\"$(wc -c < "$WORK/gw.lua" | tr -d ' ')\"}" ] || fail "ota ack wrong" "$OUT"
[ "$(kv "$OUT" REBOOTED)" = "true" ] || fail "module did not reboot after the OTA install" "$OUT"
[ "$(cmd_row "$DEV" "$CID")" = "done|$(wc -c < "$WORK/gw.lua" | tr -d ' ')" ] || fail "ota cmds row wrong" "$(cmd_row "$DEV" "$CID")"
cmp -s "$WORK/gw.lua" "$WORK/fs/ota_gw.lua" || fail "/ota_gw.lua is not byte-identical to the upload"
pass "web OTA cmd #$CID: downloaded from /api/ota/get, HMAC(gw\\n+bytes) verified, /ota_gw.lua written byte-exact, acked with the byte count, rebooted"
OUT="$(run_driver "$WORK/conf" "$FSKV")"
[ "$(kv "$OUT" GW_TAG)" = "ota" ] || fail "OTA copy not running after the reboot" "$OUT"
[ "$(kv "$OUT" OTA)" = "gw" ] || fail "gw_ota.active should be gw" "$OUT"
[ "$(kv "$OUT" POLLS)" -ge 1 ] && [ "$(kv "$OUT" TRUST)" = "trusted" ] || fail "OTA copy is not polling" "$OUT"
[ "$(kv "$OUT" BOOT_FAIL)" = "0" ] || fail "OTA copy that polls must be declared healthy" "$OUT"
DINFO="$(d1json "SELECT info FROM devices WHERE id='$DEV';" | K="$KEY" node "$WORK/dec.js" info)"
printf '%s' "$DINFO" | grep -Fq '"ota":"gw"' || fail "register after OTA should report ota=gw" "$DINFO"
pass "after reboot_cycle: OTA copy active (GW_TAG=ota, ota=gw), still polling, register blob says ota=gw, boot_fail cleared"

# =============================================================================
# 10. Wrong-slot signature: signed for gcm, queued as gw → ack fail 'hmac', file unchanged
# =============================================================================
{ cat "$WORK/gw.lua"; printf -- '-- v2\n'; } > "$WORK/gw2.lua"
HMAC_GCM="$({ printf 'gcm\n'; cat "$WORK/gw2.lua"; } | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$KEY" -r | cut -d' ' -f1)"
web -X POST "$BASE/api/ota/put?name=gw" --data-binary "@$WORK/gw2.lua" >/dev/null
CID="$(cmd_queue "$DEV" "\"type\":\"ota\",\"name\":\"gw\",\"hmac\":\"$HMAC_GCM\"")"
OUT="$(run_driver "$WORK/conf" "$FSKV")"
[ "$(kv "$OUT" LAST_ACK)" = "{\"id\":$CID,\"ok\":false,\"detail\":\"hmac\"}" ] || fail "wrong-slot signature should fail with 'hmac'" "$OUT"
[ "$(cmd_row "$DEV" "$CID")" = "failed|hmac" ] || fail "wrong-slot cmds row wrong" "$(cmd_row "$DEV" "$CID")"
cmp -s "$WORK/gw.lua" "$WORK/fs/ota_gw.lua" || fail "wrong-slot signature must not touch /ota_gw.lua"
[ "$(kv "$OUT" REBOOTED)" = "false" ] || fail "a refused OTA must not reboot" "$OUT"
pass "wrong-slot signature (signed for gcm, installed as gw): ack failed 'hmac', file untouched, no reboot"

# =============================================================================
# 11. Web bases command, signed with SMS_KEY like the OTA above (openssl, HMAC over
#     "bases\n" + the value): unsigned is refused by the Worker, a wrong signature is
#     refused by the module, a correct one sets fskv bases, acks, reboots;
#     '#url reset' by SMS undoes it
# =============================================================================
# `bases` is the only command that can take the module away for good — after it, the real
# Worker is unreachable and 拉黑/忘记 never arrive. TLS verification is off by default, so
# without a signature an on-path attacker (or a compromised Worker) could inject one. The MAC
# is over the value AS SENT under SMS_KEY, which the server never has.
bmac() { printf 'bases\n%s' "$1" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$KEY" -r | cut -d' ' -f1; }
BASES_RAW='https://127.0.0.1:9, https://127.0.0.1:10/'
BASES_NORM='https://127.0.0.1:9,https://127.0.0.1:10'
# The Worker cannot verify a MAC, so it insists one is there and passes it through: no hmac → 400.
UNSIGNED="$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: sms_session=$COOKIE" -X POST "$BASE/api/cmd" \
  -H 'Content-Type: application/json' --data "{\"dev\":\"$DEV\",\"type\":\"bases\",\"value\":\"https://127.0.0.1:9\"}")"
[ "$UNSIGNED" = "400" ] || fail "an unsigned bases must be refused by the Worker (400)" "got $UNSIGNED"
# Well-formed but signed over a different value — what a MITM or a compromised Worker can
# actually produce. The module must refuse it and leave fskv bases alone.
CIDBAD="$(cmd_queue "$DEV" "\"type\":\"bases\",\"value\":\"$BASES_RAW\",\"hmac\":\"$(bmac 'https://evil.test')\"")"
OUT="$(run_driver "$WORK/conf" "$FSKV")"
[ "$(kv "$OUT" LAST_ACK)" = "{\"id\":$CIDBAD,\"ok\":false,\"detail\":\"hmac\"}" ] || fail "wrongly-signed bases should ack 'hmac'" "$OUT"
[ "$(kv "$OUT" BASES)" = "nil" ] || fail "a wrongly-signed bases must not touch fskv bases" "$OUT"
[ "$(kv "$OUT" REBOOTED)" = "false" ] || fail "a refused bases must not reboot" "$OUT"
[ "$(cmd_row "$DEV" "$CIDBAD")" = "failed|hmac" ] || fail "wrongly-signed bases cmds row wrong" "$(cmd_row "$DEV" "$CIDBAD")"
pass "unsigned bases refused by the Worker (400); wrongly-signed bases #$CIDBAD acked 'hmac', fskv bases untouched, no reboot"
# Signed over the NORMALISED value — what the browser signs — while the raw, messy list is what
# is posted: the Worker's normalisation is the same rule, so what it stores is what was signed.
CID="$(cmd_queue "$DEV" "\"type\":\"bases\",\"value\":\"$BASES_RAW\",\"hmac\":\"$(bmac "$BASES_NORM")\"")"
OUT="$(run_driver "$WORK/conf" "$FSKV")"
[ "$(kv "$OUT" LAST_ACK)" = "{\"id\":$CID,\"ok\":true,\"detail\":\"rebooting\"}" ] || fail "bases ack wrong" "$OUT"
[ "$(kv "$OUT" BASES)" = "https://127.0.0.1:9,https://127.0.0.1:10" ] || fail "fskv bases not set" "$OUT"
[ "$(kv "$OUT" REBOOTED)" = "true" ] || fail "bases cmd must reboot" "$OUT"
[ "$(cmd_row "$DEV" "$CID")" = "done|rebooting" ] || fail "bases cmds row wrong" "$(cmd_row "$DEV" "$CID")"
pass "web bases cmd #$CID: HMAC(bases\\n+value) verified, fskv bases = https://127.0.0.1:9,https://127.0.0.1:10, acked, rebooted"
# The SMS command channel carries the same SMS_KEY signature the web buttons do, just over
# a different domain tag: mac = first 16 hex of HMAC-SHA256("sms\n" + body). Exactly what
# luatos/sms-sign.sh prints; the module recomputes it over the body it parsed out.
smsmac() { printf 'sms\n%s' "$1" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$KEY" -r | cut -d' ' -f1 | cut -c1-16; }
RESET_SMS="#url reset $(smsmac '#url reset')"
OUT="$(run_driver "$WORK/conf" "$FSKV" E2E_SMS_FROM="$SMS_FROM" E2E_SMS_TEXT="$RESET_SMS" E2E_SMS_AT=1500 E2E_TICK=3000)"
[ "$(kv "$OUT" POLLS)" = "0" ] || fail "with the new bases the local Worker must be unreachable" "$OUT"
[ "$(kv "$OUT" REBOOTED)" = "true" ] || fail "#url reset must reboot" "$OUT"
[ "$(kv "$OUT" BASES)" = "nil" ] || fail "#url reset must drop the fskv override" "$OUT"
pass "next boot polled the new (dead) bases; signed '#url reset' SMS dropped the override and rebooted"

# =============================================================================
# 12. Blocked on the web while trusted in RAM → upload 403 → message stays queued;
#     trusted again → drains
# =============================================================================
BLOCK_CMD="curl -s -o /dev/null -X POST '$BASE/api/device/trust' -H 'Cookie: sms_session=$COOKIE' -H 'Content-Type: application/json' --data '{\"id\":\"$DEV\",\"status\":\"blocked\"}'"
OUT="$(run_driver "$WORK/conf" "$FSKV" E2E_AT_MS=2000 E2E_AT_CMD="$BLOCK_CMD" E2E_SMS_TEXT="held while blocked" E2E_SMS_AT=3000)"
[ "$(kv "$OUT" UPLOAD_403)" -ge 1 ] || fail "expected the upload to be refused with 403" "$OUT"
[ "$(kv "$OUT" QUEUE)" = "1" ] || fail "403'd message must stay queued" "$OUT"
[ "$(kv "$OUT" TRUST)" = "blocked" ] || fail "the next poll should report blocked" "$OUT"
[ -n "$(kvget "$FSKV" "q:$(kv "$OUT" QSEQ)")" ] || fail "queued message not persisted in fskv"
pass "blocked mid-run: upload got 403 ($(kv "$OUT" UPLOAD_403)×), message kept + persisted, poll then said 'blocked'"
trust "$DEV" trusted
OUT="$(run_driver "$WORK/conf" "$FSKV")"
[ "$(kv "$OUT" QUEUE)" = "0" ] || fail "queue did not drain after re-trust" "$OUT"
MSG="$(d1json "SELECT id, body FROM messages ORDER BY id DESC LIMIT 1;")"
CREATED_MSGS="$CREATED_MSGS $(printf '%s' "$MSG" | node "$WORK/jcol.js" id)"
DEC="$(printf '%s' "$MSG" | K="$KEY" node "$WORK/dec.js" body)"
[ "$DEC" = '{"s":"10001","b":"held while blocked","k":"SIM 1 · 中国电信","d":"'"$DEV"'"}' ] || fail "drained message mismatch" "$DEC"
pass "trusted again: the held message drained and decrypts to the exact JSON"

echo
echo "ALL E2E ASSERTIONS PASSED"
