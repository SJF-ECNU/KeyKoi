#!/usr/bin/env bash
# 把 Swift 生物识别助手编译成本目录下的同名二进制。
# keykoid 默认在同目录查找 keykoi-biometric，也可用 --biometric-helper 或
# KEYKOI_BIOMETRIC_HELPER 指定路径。
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/keykoi-biometric.swift"
OUT="${1:-$DIR/keykoi-biometric}"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "skip: biometric helper requires macOS" >&2
  exit 0
fi

if ! command -v xcrun >/dev/null 2>&1; then
  echo "skip: xcrun not found; install the Xcode command line tools to build the Touch ID helper" >&2
  exit 0
fi

# -parse-as-library：源码用 @main 声明入口（.app 目标同样以该模式编译）。
xcrun --sdk macosx swiftc -parse-as-library -O -o "$OUT" "$SRC" \
  -framework Foundation -framework LocalAuthentication -framework Security
chmod 755 "$OUT"
echo "built $OUT" >&2
"$OUT" available >/dev/null 2>&1 || true
