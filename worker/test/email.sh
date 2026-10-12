#!/usr/bin/env bash
# Gmail → Email Routing → email() against a LOCAL wrangler dev server. Nothing remote is touched.
#
#   worker/test/email.sh            # port 8789, fresh .wrangler/state
#
# Prints one ✅ per check; exits non-zero on the first ❌.
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
    [ -n "$WPID" ] && { kill "$WPID" 2>/dev/null || true; pkill -P "$WPID" 2>/dev/null || true; }
    lsof -ti "tcp:$PORT" 2>/dev/null | xargs kill 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT
d1() {
    $WR d1 execute sms --local --json --command "$1" 2>/dev/null \
        | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{console.log(JSON.stringify(JSON.parse(s)[0].results||[]))})'
}
# send TO RAWFILE (the local trigger insists on a Message-ID, so every test mail has one) → http status of the local email trigger
send() { curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/cdn-cgi/handler/email?from=me%40gmail.com&to=$1" --data-binary "@$2"; }

MAIL_TO=$(sed -n 's/^MAIL_TO = "\(.*\)"/\1/p' wrangler.toml)
[ -n "$MAIL_TO" ] || fail "MAIL_TO missing from wrangler.toml"
npm install --no-audit --no-fund --silent

rm -rf .wrangler/state
$WR d1 execute sms --local --file=schema.sql >/dev/null 2>&1 || fail "schema.sql failed to apply"
$WR dev --port "$PORT" --local >"$LOG" 2>&1 &
WPID=$!
for i in $(seq 1 90); do
    curl -s -o /dev/null "$BASE/api/vapid" 2>/dev/null && break
    kill -0 "$WPID" 2>/dev/null || fail "wrangler dev exited early" "$(tail -20 "$LOG")"
    sleep 1
done
pass "wrangler dev up on :$PORT"

# A typical Chinese code mail: multipart, UTF-8, base64 body, RFC 2047 sender name and subject.
B64=$(printf '您的验证码是 482913，10 分钟内有效。' | base64)
cat > "$TMP/code.eml" <<MAIL
Message-ID: <1@example.com>
From: =?UTF-8?B?$(printf '某某平台' | base64)?= <noreply@example.com>
To: $MAIL_TO
Subject: =?UTF-8?B?$(printf '登录验证码' | base64)?=
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="b1"

--b1
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: base64

$B64
--b1
Content-Type: text/html; charset=UTF-8

<p>ignored</p>
--b1--
MAIL
code=$(send "$MAIL_TO" "$TMP/code.eml")
[ "${code:0:1}" = 2 ] || fail "email to MAIL_TO accepted" "$code"
row=$(d1 "SELECT sender, body FROM messages")
echo "$row" | grep -q '✉ 某某平台' || fail "sender decoded" "$row"
echo "$row" | grep -q '登录验证码\\n您的验证码是 482913' || fail "subject + text body decoded" "$row"
pass "multipart/base64/UTF-8 mail stored as '✉ 某某平台' with the code readable"

# HTML-only mail: tags stripped, code still there.
printf 'Message-ID: <2@example.com>\nFrom: a@example.com\nTo: %s\nSubject: Code\nContent-Type: text/html\n\n<html><style>p{x:1}</style><p>Your code: <b>771204</b></p></html>\n' "$MAIL_TO" > "$TMP/html.eml"
send "$MAIL_TO" "$TMP/html.eml" >/dev/null
d1 "SELECT body FROM messages ORDER BY id DESC LIMIT 1" | grep -q 'Code\\nYour code: 771204' || fail "html-only mail stripped" "$(d1 'SELECT body FROM messages ORDER BY id DESC LIMIT 1')"
pass "html-only mail stored with tags and <style> stripped"

# Any other address is rejected and stores nothing.
before=$(d1 "SELECT COUNT(*) n FROM messages")
code=$(send "other%40mail.example.com" "$TMP/code.eml")
[ "${code:0:1}" != 2 ] || fail "mail to another address rejected" "$code"
[ "$(d1 'SELECT COUNT(*) n FROM messages')" = "$before" ] || fail "rejected mail stored nothing"
pass "mail to any other address rejected, nothing stored"
