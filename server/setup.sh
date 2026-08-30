#!/usr/bin/env bash
# One-shot deploy on a fresh VPS. Idempotent — safe to re-run.
#   ./setup.sh ntfy.yourdomain.com [topic]
set -euo pipefail

DOMAIN="${1:-}"
TOPIC="${2:-sms-$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
[ -z "$DOMAIN" ] && { echo "用法: ./setup.sh ntfy.yourdomain.com [topic]"; exit 1; }

cd "$(dirname "$0")"

echo "==> 检查 DNS"
# Let's Encrypt needs the domain pointing here before Caddy can get a cert.
RESOLVED=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1 || true)
MYIP=$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || echo "")
echo "    $DOMAIN -> ${RESOLVED:-(无解析)} / 本机 -> ${MYIP:-(未知)}"
if [ -n "$MYIP" ] && [ "$RESOLVED" != "$MYIP" ]; then
    echo "    ⚠️  DNS 未指向本机。先配好 A 记录再跑，否则 Caddy 申请证书会失败。"
    read -r -p "    仍然继续？[y/N] " a; [ "$a" = "y" ] || exit 1
fi

echo "==> 放行 80/443"
# Oracle's Ubuntu images ship an iptables REJECT rule that blocks everything but SSH.
# The VCN security list must be opened separately in the Oracle web console.
if command -v iptables >/dev/null 2>&1; then
    for p in 80 443; do
        sudo iptables -C INPUT -p tcp --dport $p -j ACCEPT 2>/dev/null || \
            sudo iptables -I INPUT -p tcp --dport $p -j ACCEPT
    done
    command -v netfilter-persistent >/dev/null 2>&1 && sudo netfilter-persistent save >/dev/null 2>&1 || true
    echo "    已放行（记得同时在 Oracle 控制台的 VCN 安全列表放行 80/443）"
fi

echo "==> 写入域名"
sed -i.bak "s|ntfy\.yourdomain\.com|$DOMAIN|g" Caddyfile ntfy/server.yml
rm -f Caddyfile.bak ntfy/server.yml.bak

echo "==> 启动容器"
docker compose up -d
sleep 8

echo "==> 创建账号（交互输入密码）"
docker compose exec ntfy ntfy user list 2>/dev/null | grep -q "^user me" \
    || docker compose exec ntfy ntfy user add me
docker compose exec ntfy ntfy access me "$TOPIC" rw

echo "==> 签发 token"
TOKEN=$(docker compose exec -T ntfy ntfy token add me | grep -oE 'tk_[A-Za-z0-9]+' | head -1)

echo "==> 验证"
sleep 3
CODE=$(curl -fsS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
    -d "setup ok" "https://$DOMAIN/$TOPIC" 2>/dev/null || echo "000")
ANON=$(curl -fsS -o /dev/null -w '%{http_code}' -d x "https://$DOMAIN/$TOPIC" 2>/dev/null || echo "000")

echo
if [ "$CODE" = "200" ]; then
    echo "✅ HTTPS + token 发布正常"
else
    echo "❌ 发布失败（HTTP $CODE）。看日志：docker compose logs caddy"
fi
[ "$ANON" = "403" ] && echo "✅ 匿名访问已拒绝" || echo "⚠️  匿名访问返回 $ANON，预期 403"

cat <<EOF

把下面三行加进 android/local.properties（注释不要写在同一行）：

NTFY_URL=https://$DOMAIN
NTFY_TOPIC=$TOPIC
NTFY_TOKEN=$TOKEN

然后重新编译安装，并在手机上打开一次 app。
停服务用 docker compose down —— 千万别加 -v，那会删掉账号和 token。
EOF
