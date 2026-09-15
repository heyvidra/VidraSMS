#!/usr/bin/env bash
# ota-sign.sh <gw|gcm> — print the HMAC-SHA256 the module checks before
# installing luatos/<name>.lua, as the "#ota <name> <hmac>" SMS line. The MAC is
# computed under SMS_KEY (raw 32 bytes of the 64-hex key file) over
# "<name>\n" + file — exactly what main.lua verifies and what the web page's
# 更新脚本 button computes in the browser. Normally you just use that button;
# this is for the optional OWNER SMS path: upload the same file on the web
# (/api/ota/put via 更新脚本, or curl), then send the printed line.
#
#   bash luatos/test/ota-sign.sh gw
#   → #ota gw <64 hex>
#
# Env: SMS_KEY_FILE — path of the 64-hex key file (default worker/.sms_key).
# The key is read at runtime only; nothing is written anywhere.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NAME="${1:-}"
case "$NAME" in
  gw|gcm) ;;
  *) echo "usage: $0 <gw|gcm>" >&2; exit 2 ;;
esac

FILE="$REPO/luatos/$NAME.lua"
[ -f "$FILE" ] || { echo "missing $FILE" >&2; exit 2; }
luac -p "$FILE" 2>/dev/null || { echo "$FILE does not compile — the module would reject it" >&2; exit 2; }

KEYFILE="${SMS_KEY_FILE:-$REPO/worker/.sms_key}"
[ -r "$KEYFILE" ] || { echo "cannot read key file $KEYFILE (set SMS_KEY_FILE)" >&2; exit 2; }
KEY="$(tr -d '[:space:]' < "$KEYFILE")"
[[ "$KEY" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "key file must hold exactly 64 hex chars: $KEYFILE" >&2; exit 2; }

# Signed data is "<name>\n<file bytes>" — the target name is bound into the MAC
# so a signature made for gw cannot be replayed as "#ota gcm …" (main.lua ota_install).
MAC="$({ printf '%s\n' "$NAME"; cat "$FILE"; } | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$KEY" -r | cut -d' ' -f1)"
printf '#ota %s %s\n' "$NAME" "$MAC"
printf 'upload luatos/%s.lua unchanged (%s bytes) on the web first, then send the line above from the OWNER phone\n' \
  "$NAME" "$(wc -c < "$FILE" | tr -d ' ')" >&2
