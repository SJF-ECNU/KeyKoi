#!/usr/bin/env bash
# 卸载 KeyKoi launchd 服务。数据默认保留，--purge 才会删除密钥库目录。
set -euo pipefail
PREFIX="${KEYKOI_PREFIX:-$HOME/Library/Application Support/KeyKoi}"
LABEL="${KEYKOI_LABEL:-com.keykoi.keykoid}"
PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --purge) PURGE=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
if [ "$PURGE" = "1" ]; then
  rm -rf "$PREFIX"
  echo "removed $PREFIX (encrypted vault included)"
else
  echo "removed launch agent; data kept at $PREFIX"
fi
