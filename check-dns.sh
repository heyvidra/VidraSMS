#!/usr/bin/env bash
# Snapshot a domain's DNS before moving nameservers, and diff it afterwards.
#
#   ./check-dns.sh example.com > before.txt     # BEFORE changing nameservers at GoDaddy
#   ./check-dns.sh example.com > after.txt      # after Cloudflare says the zone is Active
#   diff before.txt after.txt
#
# Anything that disappears between the two — an MX line especially — is mail or a service
# that will stop working, and is far easier to fix now than to notice next week.
set -euo pipefail

DOMAIN="${1:-}"
[ -z "$DOMAIN" ] && { echo "用法: ./check-dns.sh example.com"; exit 1; }

# Query an authoritative-ish public resolver rather than the local one, so a stale local
# cache does not make the two snapshots look identical when they are not.
R="@1.1.1.1"

echo "# DNS snapshot: $DOMAIN"
echo

echo "## NS (公共解析器看到的 —— 会受缓存影响)"
dig +short $R NS "$DOMAIN" | sort
echo

# During a nameserver migration the registry updates its whois database immediately but
# republishes the DNS zone on its own schedule, so these two can disagree for a while.
# Reading both is the difference between "my change failed" and "the registry hasn't
# published yet" — which look identical if you only ask a resolver.
TLD="${DOMAIN##*.}"
TLDNS=$(dig +short NS "$TLD." @1.1.1.1 2>/dev/null | head -1)
echo "## NS (注册局 DNS 区文件 —— 无缓存，这是全球解析的依据)"
if [ -n "$TLDNS" ]; then
    dig +norec NS "$DOMAIN" @"$TLDNS" 2>/dev/null \
        | awk '/^'"$DOMAIN"'\./ && $4=="NS" {print "    "$5}' | sort
else
    echo "    (查不到 .$TLD 的权威服务器)"
fi
echo

echo "## NS (注册局 whois 数据库 —— 改完立刻更新，先于区文件)"
whois -h "whois.nic.$TLD" "$DOMAIN" 2>/dev/null \
    | grep -i "^ *Name Server:" | awk '{print "    "tolower($3)}' | sort -u \
    || echo "    (whois 查询失败)"
echo

echo "## DNSSEC (搬 NS 前必须先在 GoDaddy 关掉，否则域名会整个解析失败)"
DS=$(dig +short $R DS "$DOMAIN" | sort)
if [ -n "$DS" ]; then
    echo "$DS"
    echo ">>> ⚠️  检测到 DS 记录，DNSSEC 是开着的。先去 GoDaddy 关掉 DNSSEC，"
    echo ">>>    等旧记录过期（通常几小时）再改 NS。顺序反了域名会打不开。"
else
    echo "(无 DS 记录 —— DNSSEC 未启用，可以直接改 NS)"
fi
echo

echo "## MX (邮箱。这几行搬完必须还在，否则收不到邮件)"
dig +short $R MX "$DOMAIN" | sort
echo

echo "## TXT (SPF / DKIM / DMARC / 各种域名验证)"
dig +short $R TXT "$DOMAIN" | sort
echo

echo "## A / AAAA / CNAME (根域名)"
dig +short $R A "$DOMAIN" | sort
dig +short $R AAAA "$DOMAIN" | sort
dig +short $R CNAME "$DOMAIN" | sort
echo

echo "## 常见子域名"
for sub in www mail smtp imap pop autodiscover _dmarc sms; do
    OUT=$(dig +short $R A "$sub.$DOMAIN"; dig +short $R CNAME "$sub.$DOMAIN"; \
          dig +short $R TXT "$sub.$DOMAIN")
    [ -n "$OUT" ] && echo "$sub: $(echo "$OUT" | tr '\n' ' ')"
done
echo

echo "# 生成时间: $(date '+%Y-%m-%d %H:%M:%S %Z')"
