#!/usr/bin/env bash
# One-shot deploy to Cloudflare Workers. Idempotent — safe to re-run.
#   ./setup.sh
# Requires: node, and a Cloudflare account (free plan, no card needed).
set -euo pipefail

cd "$(dirname "$0")"
WR="npx wrangler"

echo "==> 登录 Cloudflare（浏览器会弹出授权页）"
$WR whoami >/dev/null 2>&1 || $WR login

echo "==> 创建 D1 数据库"
# `d1 list` is the source of truth: `d1 info <name>` has been observed exiting non-zero
# even when the database exists, which made an earlier version try to create a duplicate.
# Parse with node rather than grep — wrangler pretty-prints the JSON one field per line,
# so "uuid" and "name" never share a line and any line-oriented regex silently finds nothing.
find_db() {
    $WR d1 list --json 2>/dev/null | node -e '
        let s = "";
        process.stdin.on("data", d => s += d).on("end", () => {
            try {
                const db = JSON.parse(s).find(x => x.name === "sms");
                if (db && db.uuid) console.log(db.uuid);
            } catch { /* not JSON — caller reports the empty result */ }
        });
    '
}

DB_ID=$(find_db || true)
if [ -n "$DB_ID" ]; then
    echo "    已存在，跳过创建"
else
    # Creating a duplicate is a hard error, so tolerate it and re-read the list.
    $WR d1 create sms || echo "    （创建返回错误，改为直接查询）"
    DB_ID=$(find_db || true)
fi

case "$DB_ID" in
    ????????-????-????-????-????????????) ;;
    *)
        echo "    ❌ 取不到 database_id（拿到的是 '$DB_ID'）。"
        echo "       请运行 npx wrangler d1 list，把 sms 那行的 uuid 手动填进 wrangler.toml。"
        exit 1
        ;;
esac
sed -i.bak "s/^database_id = .*/database_id = \"$DB_ID\"/" wrangler.toml && rm -f wrangler.toml.bak
echo "    database_id = $DB_ID"

echo "==> 建表"
$WR d1 execute sms --remote --file=schema.sql

echo "==> 设置密钥"
# Secrets cannot be read back, so regenerating the token on every run would silently
# invalidate the one already in local.properties. Only create what is missing.
EXISTING=$($WR secret list 2>/dev/null || echo "")
TOKEN=""

if echo "$EXISTING" | grep -q "SEND_TOKEN"; then
    echo "    SEND_TOKEN 已存在，保留不动（继续用 local.properties 里那个）"
else
    TOKEN="tk_$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    echo "$TOKEN" | $WR secret put SEND_TOKEN
fi

if echo "$EXISTING" | grep -q "WEB_USER"; then
    echo "    WEB_USER 已存在，保留不动"
else
    echo "    设置网页登录用户名："
    $WR secret put WEB_USER
fi

if echo "$EXISTING" | grep -q "WEB_PASS"; then
    echo "    WEB_PASS 已存在，保留不动"
else
    echo "    设置网页登录密码："
    $WR secret put WEB_PASS
fi

# Signs the login cookie. Random and never shown — you never need to know it.
# Rotating it (delete the secret and re-run) logs every browser out.
if echo "$EXISTING" | grep -q "SESSION_SECRET"; then
    echo "    SESSION_SECRET 已存在，保留不动"
else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | $WR secret put SESSION_SECRET
    echo "    SESSION_SECRET 已自动生成"
fi

# The encryption key is deliberately NOT a Worker secret — the server must never hold it.
# It goes into the phone's local.properties and the browser's localStorage, nowhere else.
KEYFILE=".sms_key"
if [ -f "$KEYFILE" ]; then
    SMS_KEY=$(cat "$KEYFILE")
    echo "    加密密钥已存在（$KEYFILE），沿用"
else
    SMS_KEY=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    echo "$SMS_KEY" > "$KEYFILE"
    chmod 600 "$KEYFILE"
    echo "    加密密钥已生成并存到 $KEYFILE（已 gitignore）"
fi

echo "==> 部署"
$WR deploy

TOPIC=$(sed -n 's/^TOPIC = "\(.*\)"/\1/p' wrangler.toml)
HOST=$(sed -n 's/.*pattern = "\([^"]*\)".*/\1/p' wrangler.toml | head -1)
[ -n "$TOKEN" ] && TOKEN_LINE="NTFY_TOKEN=$TOKEN" \
    || TOKEN_LINE="NTFY_TOKEN=（沿用你上次记下的那个，本次未重新生成）"
cat <<EOF

完成。把下面四行填进 android/local.properties（注释不要写在同一行）：

NTFY_URL=https://$HOST
NTFY_TOPIC=$TOPIC
$TOKEN_LINE
SMS_KEY=$SMS_KEY

⚠️  SMS_KEY 是端到端加密的密钥，服务器上没有它。
    首次在浏览器打开 https://$HOST 后，点右上角「密钥」把同一串填进去才能看到内容。
    这串丢了，已存的消息就永远解不开 —— 建议存进密码管理器。

然后 cd ../android && ./gradlew assembleDebug，装到插 SIM 卡的手机上，打开一次 app。
EOF
