#!/usr/bin/env bash
# KeyKoi macOS 安装/升级脚本：安装二进制、适配声明与 launchd 后台服务。
# 默认前缀是 ~/Library/Application Support/KeyKoi，数据目录在 <prefix>/data。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PREFIX="${KEYKOI_PREFIX:-$HOME/Library/Application Support/KeyKoi}"
LABEL="${KEYKOI_LABEL:-com.keykoi.keykoid}"
GATEWAY="${KEYKOI_GATEWAY:-127.0.0.1:8377}"
ADMIN="${KEYKOI_ADMIN:-127.0.0.1:8378}"
LOAD=1

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --gateway) GATEWAY="$2"; shift 2 ;;
    --admin) ADMIN="$2"; shift 2 ;;
    --no-load) LOAD=0; shift ;;
    --pidfile) PIDFILE="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$PREFIX/bin" "$PREFIX/data" "$PREFIX/adapters"
chmod 700 "$PREFIX/data"

echo "building KeyKoi"
(cd "$ROOT" && go build -o "$PREFIX/bin/keykoi" ./cmd/keykoi && go build -o "$PREFIX/bin/keykoid" ./cmd/keykoid)
cp "$ROOT"/adapters/*.yaml "$PREFIX/adapters/" 2>/dev/null || true
chmod 755 "$PREFIX/bin/keykoi" "$PREFIX/bin/keykoid"

# 生物识别助手（可选）：keykoid 默认在同目录查找 keykoi-biometric。
# 需要 Xcode 命令行工具；编译失败不阻塞安装，生物识别解锁会明确报告
# AUTH_UNAVAILABLE 并回退主密码。
if [ "${KEYKOI_SKIP_BIOMETRIC:-0}" != "1" ] && [ -f "$ROOT/packaging/macos/keykoi-biometric.swift" ]; then
  if bash "$ROOT/packaging/macos/build-biometric.sh" "$PREFIX/bin/keykoi-biometric" >/dev/null 2>&1; then
    chmod 755 "$PREFIX/bin/keykoi-biometric"
    echo "installed Touch ID helper to $PREFIX/bin/keykoi-biometric"
  else
    echo "note: Touch ID helper was not built; biometric unlock will report AUTH_UNAVAILABLE"
  fi
fi

# 可选：用本机的 Apple Development / Developer ID 身份给助手签名，让 Keychain
# 接受 keychain-access-groups（生物 ACL 需要）。默认关闭，设置
# KEYKOI_SIGN_BIOMETRIC=1 才执行；没有签名身份时脚本退出码 2 并打印准备步骤，
# 安装流程继续，主密码回退仍然可用。
if [ "${KEYKOI_SIGN_BIOMETRIC:-0}" = "1" ] && [ -x "$PREFIX/bin/keykoi-biometric" ]; then
  echo "signing the Touch ID helper (KEYKOI_SIGN_BIOMETRIC=1)"
  SIGN_LOG="$PREFIX/data/sign-biometric.log"
  if bash "$ROOT/packaging/macos/sign-biometric.sh" --helper "$PREFIX/bin/keykoi-biometric" >"$SIGN_LOG" 2>&1; then
    grep -E '^(identity|team|provision|entitlements_keychain_access_groups|codesign_verify|launch_probe|deploy)[:=]' "$SIGN_LOG" | sed 's/^/  /' || true
    echo "signing log: $SIGN_LOG"
    if grep -q '^deploy=reverted' "$SIGN_LOG"; then
      echo "note: 签名成功但系统拒绝启动该助手（缺少描述文件授权），已回滚；见 $SIGN_LOG"
    fi
  else
    SIGN_CODE=$?
    echo "note: Touch ID helper signing stopped with exit $SIGN_CODE; see $SIGN_LOG"
  fi
fi

# 生物识别 .app（默认部署）：免费 Personal Team 签发的描述文件只有 7 天有效期，
# 因此助手以已签名的 `KeyKoi Biometric.app` 形式分发，由
# install-biometric-app.sh 负责「部署 + 临期重建」，install-biometric-renew.sh
# 负责每周自动续签。这里只做「有构建产物就部署」，没有产物时不算安装失败。
# 设 KEYKOI_BIOMETRIC_APP=0 可完全跳过这一步。
BIOMETRIC_APP_HELPER=""
APP_INSTALL_SCRIPT="$ROOT/packaging/macos/install-biometric-app.sh"
if [ "${KEYKOI_BIOMETRIC_APP:-1}" != "0" ] && [ -f "$APP_INSTALL_SCRIPT" ]; then
  APP_LOG="$PREFIX/data/install-biometric-app.log"
  if bash "$APP_INSTALL_SCRIPT" --deploy-only --prefix "$PREFIX" \
       --team "${KEYKOI_DEV_TEAM:-977QNJU6V6}" >"$APP_LOG" 2>&1; then
    BIOMETRIC_APP_HELPER="$PREFIX/KeyKoi Biometric.app/Contents/MacOS/keykoi-biometric"
    echo "installed KeyKoi Biometric.app to $PREFIX/KeyKoi Biometric.app"
    grep -E '^(deployed_app|profile_expiry|remaining_days|signature_team|codesign_verify|entitlements_keychain_access_groups)=' \
      "$APP_LOG" | sed 's/^/  /' || true
    echo "  helper: $BIOMETRIC_APP_HELPER"
  else
    echo "note: KeyKoi Biometric.app was not deployed; biometric unlock falls back to the master password"
    echo "      build + deploy: bash packaging/macos/install-biometric-app.sh --build-if-needed --prefix \"$PREFIX\""
    echo "      log: $APP_LOG"
  fi
fi

PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
mkdir -p "$HOME/Library/LaunchAgents"

# 只有真正部署了 .app 才把 KEYKOI_BIOMETRIC_HELPER 写进 launchd 环境；
# 否则 keykoid 仍按 <prefix>/bin/keykoi-biometric 或 PATH 查找。
ENV_BLOCK=""
if [ -n "$BIOMETRIC_APP_HELPER" ]; then
  ENV_BLOCK="  <key>EnvironmentVariables</key>
  <dict>
    <key>KEYKOI_BIOMETRIC_HELPER</key><string>$BIOMETRIC_APP_HELPER</string>
  </dict>"
fi

cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PREFIX/bin/keykoid</string>
    <string>--data-dir</string><string>$PREFIX/data</string>
    <string>--adapters</string><string>$PREFIX/adapters</string>
    <string>--gateway</string><string>$GATEWAY</string>
    <string>--admin</string><string>$ADMIN</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Interactive</string>
$ENV_BLOCK
  <key>StandardOutPath</key><string>$PREFIX/data/keykoid.out.log</string>
  <key>StandardErrorPath</key><string>$PREFIX/data/keykoid.err.log</string>
  <key>Umask</key><integer>63</integer>
</dict>
</plist>
PLISTEOF
chmod 600 "$PLIST"

echo "installed binaries to $PREFIX"
echo "launch agent: $PLIST"

if [ "$LOAD" = "1" ]; then
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  # bootout 是异步的，立即 bootstrap 会得到 EIO；等标签真正卸载后再加载。
  for i in $(seq 1 50); do
    launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || break
    sleep 0.1
  done
  ok=0
  for i in $(seq 1 10); do
    if launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>"$PREFIX/data/bootstrap.err"; then
      ok=1
      break
    fi
    sleep 0.3
  done
  if [ "$ok" != "1" ]; then
    echo "launchctl bootstrap failed: $(cat "$PREFIX/data/bootstrap.err" 2>/dev/null)" >&2
    exit 1
  fi
  launchctl kickstart -k "gui/$(id -u)/$LABEL"
  echo "keykoid started under launchd ($LABEL)"
fi
