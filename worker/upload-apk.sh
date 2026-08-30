#!/usr/bin/env bash
# Push the latest signed release APK to the KV key that 777310753.xyz/app serves.
# Run after: (cd ../android && ./gradlew assembleRelease)
set -euo pipefail
cd "$(dirname "$0")"

APK="../android/app/build/outputs/apk/release/app-release.apk"
[ -f "$APK" ] || { echo "找不到 release APK，先跑 (cd ../android && ./gradlew assembleRelease)"; exit 1; }

# The namespace id comes from wrangler.toml's [[kv_namespaces]] APK binding.
NS=$(sed -n '/binding = "APK"/,/id = /{s/.*id = "\([^"]*\)".*/\1/p;}' wrangler.toml | head -1)
[ -n "$NS" ] || { echo "wrangler.toml 里没找到 APK 的 KV id"; exit 1; }

echo "上传 $(wc -c < "$APK") 字节到线上 KV…"
npx wrangler kv key put app --path "$APK" --namespace-id "$NS" --remote

echo "完成。777310753.xyz/app 现在就是这个新版本（无需重新部署 Worker）。"
