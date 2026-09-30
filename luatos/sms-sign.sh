#!/usr/bin/env bash
# sms-sign.sh '<#command>' — print the exact SMS text to send to the module.
#
# The module executes a "#" SMS only when it carries a MAC over the command under
# SMS_KEY, so nothing about the channel depends on a phone number (a caller ID is
# trivially spoofable; this is not). Output is one line:
#
#     <body> <mac>
#
# mac = the first 16 hex chars of HMAC-SHA256("sms\n" + body) with SMS_KEY as the
# raw 32-byte key. main.lua computes the same thing (sms_cmd / sms_signed) over the
# same canonical body: the whole message trimmed, the last whitespace-separated
# token split off as the mac, the remainder trimmed again.
#
#   bash luatos/sms-sign.sh '#status'
#   bash luatos/sms-sign.sh '#reboot'
#   bash luatos/sms-sign.sh '#url https://a.com,https://b.com'
#   bash luatos/sms-sign.sh '#url reset'
#   bash luatos/sms-sign.sh '#ota clear'
#   bash luatos/sms-sign.sh "$(bash luatos/test/ota-sign.sh gw)"   # → #ota gw <hmac> <mac>
#
# The last form is why ota-sign.sh prints a whole "#ota gw <hmac>" line: that file
# HMAC is part of the body, and this script signs the body as a whole.
#
# Env: SMS_KEY_FILE — path of the 64-hex key file (default worker/.sms_key).
# The key is read at runtime only; nothing is written anywhere.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BODY="${1-}"
[ $# -eq 1 ] || { echo "usage: $0 '<#command>'   (quote it — it contains spaces)" >&2; exit 2; }

# The canonical body, byte-for-byte what main.lua signs: trim both ends. Everything
# inside is signed verbatim, spaces included.
BODY="${BODY#"${BODY%%[![:space:]]*}"}"
BODY="${BODY%"${BODY##*[![:space:]]}"}"
case "$BODY" in
  "#"*) ;;
  *) echo "the command must start with '#': got '$BODY'" >&2; exit 2 ;;
esac
# A mac is split off as the LAST whitespace-separated token, so a body must have
# something before its last token — and control characters have no place in an SMS.
case "$BODY" in
  *[$'\n\r\t']*) echo "the command must be a single line without tabs" >&2; exit 2 ;;
esac

KEYFILE="${SMS_KEY_FILE:-$REPO/worker/.sms_key}"
[ -r "$KEYFILE" ] || { echo "cannot read key file $KEYFILE (set SMS_KEY_FILE)" >&2; exit 2; }
KEY="$(tr -d '[:space:]' < "$KEYFILE")"
[[ "$KEY" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "key file must hold exactly 64 hex chars: $KEYFILE" >&2; exit 2; }

# printf with a real newline between the "sms" domain tag and the body — the tag keeps
# this signature from ever being mistaken for the "bases\n…" / "<name>\n…" ones.
MAC="$(printf 'sms\n%s' "$BODY" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$KEY" -r | cut -d' ' -f1 | cut -c1-16)"
[ "${#MAC}" -eq 16 ] || { echo "openssl did not produce a MAC" >&2; exit 2; }

printf '%s %s\n' "$BODY" "$MAC"
LINE=$((${#BODY} + 17))
[ "$LINE" -le 160 ] || printf 'warning: %s characters — over the 160-char single-SMS budget\n' "$LINE" >&2
printf 'send that line to the module from any phone; it replies to the sender. Anyone can read it, nobody can change it.\n' >&2
