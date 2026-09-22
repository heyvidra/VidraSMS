#!/usr/bin/env bash
# pack.sh — build the seller package: luatos/dist/smsgw-<VERSION>.zip holding
# main.lua, gw.lua, gcm.lua and YOUR config.lua (SMS_KEY filled in), then print
# the paragraph to paste to the seller. Refuses to run until config.lua exists
# and its SMS_KEY is 64 hex (not the placeholder). Nothing is read from
# worker/.sms_key here — you copy the key into config.lua yourself.
#
#   bash luatos/pack.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFG="$HERE/config.lua"
[ -f "$CFG" ] || { echo "missing $CFG — copy config.lua.example to config.lua and fill in SMS_KEY" >&2; exit 2; }
KEY="$(sed -nE 's/^[[:space:]]*SMS_KEY[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' "$CFG" | head -1)"
[[ "$KEY" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "config.lua: SMS_KEY must be exactly 64 hex chars (cat worker/.sms_key), got '${KEY:0:8}…'" >&2; exit 2; }
[[ "$KEY" =~ ^0{64}$ ]] && { echo "config.lua: SMS_KEY is all zeros — the module refuses that key" >&2; exit 2; }
for f in main.lua gw.lua gcm.lua config.lua; do
  luac -p "$HERE/$f" || { echo "$f does not compile" >&2; exit 2; }
done

# Luatools decides which lib files a project needs by scanning the script TEXT, and on a line that
# mentions require it reads FIRST-QUOTE-to-LAST-QUOTE as the module name. Two quoted strings on
# such a line therefore make it demand a file with a nonsense name and refuse to flash --
# "合并失败: 缺少 ...请添加" -- even with 添加默认lib ticked. That cost a round trip to the person
# doing the flashing once; never ship a package that trips it again.
for f in main.lua gw.lua gcm.lua config.lua; do
  BAD="$(awk '/require/ { n = gsub(/"/, "&"); if (n > 2) printf "%d: %s\n", NR, $0 }' "$HERE/$f")"
  [ -z "$BAD" ] || {
    echo "$f: a line mentioning require carries more than one quoted string." >&2
    echo "  Luatools reads first-quote-to-last-quote as the module name and will refuse to flash." >&2
    printf '%s\n' "$BAD" >&2
    exit 2
  }
done
# The scanner is also what makes Luatools DEMAND a file. main.lua loads gw and gcm through an
# alias the scanner cannot read, so without an explicit mention it happily flashes a package with
# both files missing -- which is exactly how one board shipped boot-looping on "module 'gw' not
# found". Keep the inert mentions alive.
for m in gw gcm; do
  grep -qE "require\\(\"$m\"\\)" "$HERE/main.lua" || {
    echo "main.lua no longer mentions require(\"$m\") on any line." >&2
    echo "  Luatools would then flash a package WITHOUT $m.lua and the module would boot-loop." >&2
    exit 2
  }
done

VER="$(sed -nE 's/^VERSION[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' "$HERE/main.lua" | head -1)"
[ -n "$VER" ] || { echo "cannot read VERSION from main.lua" >&2; exit 2; }

mkdir -p "$HERE/dist"
OUT="$HERE/dist/smsgw-$VER.zip"
rm -f "$OUT"
( cd "$HERE" && zip -q -j "$OUT" main.lua gw.lua gcm.lua config.lua )
echo "built $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes; VERSION $VER)"
echo "this zip CONTAINS your SMS_KEY — send it only to the person flashing the module"
echo
cat <<'TXT'
———— 粘贴给卖家 ————
麻烦用 Luatools 刷一下：新建项目 → 底层选 LuatOS-SoC_V2052_Air780EHV_101.soc（我自己提供）→
添加 zip 里的 4 个脚本（main.lua、gw.lua、gcm.lua、config.lua）→ 勾选「添加默认lib」→
点「下载底层和脚本」→ 下载完在日志里看到 smsgw 字样即可。

⚠️ 四个脚本必须全部添加，缺一个都会刷出一块开不了机的板子（工具不一定会提示）。
⚠️ 核心板通电不会自动开机：拨到 ON 之后要按住「开机」键 2 秒。
TXT
