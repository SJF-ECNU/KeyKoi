#!/usr/bin/env bash
# install-biometric-app.sh 的安全属性自检（缺陷 32 回归用）。
#
# 只跑「候选校验 / 状态传播 / 不破坏现有安装」这几条不需要真实 Apple 签名身份的断言：
#   · 描述文件解析（到期时间、TeamIdentifier、App ID、keychain-access-groups）在
#     用 openssl 现造的 CMS 描述文件上是否正确；这些函数从安装脚本里原样取出执行，
#     不复制实现，改名就会在这里炸掉；
#   · 候选 .app 不合格（未签名 / 签名团队不符 / 描述文件过期 / 缺描述文件）时
#     --deploy-only 与非零退出、且现有安装字节不变；
#   · 构建脚本报告了不可用产物时，--build-if-needed 不拿它顶替当前助手；
#   · 状态检查失败不会被当成成功打印（静态断言：ok 收尾只有 conclude_after_deploy 一处）；
#   · 脚本仍然不调用助手的 store/load/delete；
#   · Swift 重新登记路径先写暂存项、读回比对，再原子更新正式项，且没有撤旧写新回退。
#
# 不写用户目录、不碰 Keychain、不构建 Xcode 工程：全部在 mktemp 目录里做。
# Swift 检查只是静态源码断言，不代表测试过真实 Touch ID 或 Keychain ACL 行为。
# 退出码：0 全部通过；1 有断言失败。
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP_SCRIPT="$ROOT/packaging/macos/install-biometric-app.sh"
BIOMETRIC_SRC="$ROOT/packaging/macos/keykoi-biometric.swift"
TEAM="${KEYKOI_DEV_TEAM:-977QNJU6V6}"
BUNDLE_NAME="KeyKoi Biometric.app"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-install-selfcheck.XXXXXX")"
PREFIX="$WORK/prefix"
DERIVED="$WORK/derived"
APP="$PREFIX/$BUNDLE_NAME"
OUT="$WORK/out"
ERR="$WORK/err"
PASSED=0
FAILED=0

log() { printf '%s\n' "$*" >&2; }
ok() { PASSED=$((PASSED + 1)); log "PASS $1"; }
bad() { FAILED=$((FAILED + 1)); log "FAIL $1${2:+ ($2)}"; }
check_is() { # 名字 期望 实际
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected=$2 actual=$3"; fi
}
check_contains() { # 名字 子串 文件
  if grep -qF -- "$2" "$3" 2>/dev/null; then ok "$1"; else bad "$1" "missing '$2'"; fi
}
check_absent() { # 名字 子串 文件
  if grep -qF -- "$2" "$3" 2>/dev/null; then bad "$1" "unexpected '$2'"; else ok "$1"; fi
}
cleanup() {
  if [ "${KEEP_WORK:-0}" = "1" ]; then log "work dir kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# ---- 现造一份 CMS 描述文件（openssl 自签，只用于解析测试） ----
have_openssl=yes
command -v openssl >/dev/null 2>&1 || have_openssl=no

make_profile() { # out team appid expiry-iso [groups]
  local out="$1" team="$2" appid="$3" expiry="$4" groups="${5:-$4}"
  groups="${5:-$appid}"
  local plist="$out.plist"
  cat >"$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>AppIDName</key><string>KeyKoi Biometric</string>
  <key>TeamIdentifier</key><array><string>$team</string></array>
  <key>ExpirationDate</key><date>$expiry</date>
  <key>UUID</key><string>11111111-2222-3333-4444-555555555555</string>
  <key>Entitlements</key>
  <dict>
    <key>com.apple.application-identifier</key><string>$appid</string>
    <key>keychain-access-groups</key><array><string>$groups</string></array>
  </dict>
</dict>
</plist>
PLIST
  openssl smime -sign -in "$plist" -signer "$WORK/cert.pem" -inkey "$WORK/cert.key" \
    -outform der -nodetach -out "$out" >/dev/null 2>&1
}

# 从安装脚本里取出一个函数定义（实现只有一处，改名就会在这里失败）。
extract_fn() { # 函数名 脚本
  awk -v fn="$1" 'index($0, fn "() {") == 1 {p=1} p {print} p && $0 == "}" {exit}' "$2"
}

# ---- 造一个候选 .app（默认 ad-hoc 签名；--unsigned 时不签） ----
make_app() { # dir [--unsigned] [--profile FILE]
  local dir="$1"; shift
  local sign=yes profile=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --unsigned) sign=no; shift ;;
      --profile) profile="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  mkdir -p "$dir/Contents/MacOS"
  cat >"$dir/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.keykoi.biometric</string>
  <key>CFBundleExecutable</key><string>keykoi-biometric</string>
  <key>CFBundlePackageType</key><string>APPL</string>
</dict>
</plist>
PLIST
  printf '#!/bin/sh\nexit 4\n' >"$dir/Contents/MacOS/keykoi-biometric"
  chmod +x "$dir/Contents/MacOS/keykoi-biometric"
  [ -n "$profile" ] && cp "$profile" "$dir/Contents/embedded.provisionprofile"
  if [ "$sign" = "yes" ]; then
    codesign --force --deep --sign - "$dir" >/dev/null 2>&1
  fi
}

# 预置一个「现有安装」，用来验证失败路径不动它。
seed_install() {
  rm -rf "$APP"
  mkdir -p "$APP/Contents/MacOS"
  printf 'old-install\n' >"$APP/Contents/MacOS/marker"
  printf '#!/bin/sh\nexit 4\n' >"$APP/Contents/MacOS/keykoi-biometric"
  chmod +x "$APP/Contents/MacOS/keykoi-biometric"
  ( cd "$APP" && find . -type f -exec shasum -a 256 {} + | sort )
}
install_fingerprint() {
  ( cd "$APP" && find . -type f -exec shasum -a 256 {} + | sort )
}

log "== 1. 描述文件解析（从安装脚本取出的函数） =="
if [ "$have_openssl" = "no" ]; then
  log "SKIP 1（没有 openssl，无法现造 CMS 描述文件）"
else
  mkdir -p "$WORK/parse"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/cert.key" \
    -out "$WORK/cert.pem" -days 2 -subj "/CN=keykoi-selfcheck" >/dev/null 2>&1
  # 只取需要的函数定义，实现仍来自安装脚本本身。
  for fn in profile_field profile_team profile_app_id read_expiry profile_remaining_seconds; do
    eval "$(extract_fn "$fn" "$APP_SCRIPT")"
  done
  now_epoch() { date +%s; }
  FUTURE="$(date -u -v+7d +%Y-%m-%dT%H:%M:%SZ)"
  PAST="$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ)"
  make_profile "$WORK/parse/good.profile" "$TEAM" "$TEAM.com.keykoi.biometric" "$FUTURE"
  make_profile "$WORK/parse/expired.profile" "$TEAM" "$TEAM.com.keykoi.biometric" "$PAST"
  make_profile "$WORK/parse/otherteam.profile" "ZZZZZZZZZZ" "ZZZZZZZZZZ.com.keykoi.biometric" "$FUTURE"

  check_is "profile_team 读出团队" "$TEAM" "$(profile_team "$WORK/parse/good.profile")"
  check_is "profile_app_id 读出 App ID" "$TEAM.com.keykoi.biometric" \
    "$(profile_app_id "$WORK/parse/good.profile")"
  check_is "read_expiry 读出原始到期时间" "$FUTURE" \
    "$(read_expiry "$WORK/parse/good.profile" | cut -f1)"
  remaining="$(profile_remaining_seconds "$WORK/parse/good.profile")"
  if [ -n "$remaining" ] && [ "$remaining" -gt 600000 ]; then
    ok "未过期描述文件的剩余秒数为正（${remaining}）"
  else
    bad "未过期描述文件的剩余秒数为正" "got=$remaining"
  fi
  remaining="$(profile_remaining_seconds "$WORK/parse/expired.profile")"
  if [ -n "$remaining" ] && [ "$remaining" -lt 0 ]; then
    ok "已过期描述文件的剩余秒数为负（${remaining}）"
  else
    bad "已过期描述文件的剩余秒数为负" "got=$remaining"
  fi
  check_is "团队不符的描述文件被读成别的团队" "ZZZZZZZZZZ" \
    "$(profile_team "$WORK/parse/otherteam.profile")"
  check_is "描述文件损坏时读不到到期时间" "" \
    "$(read_expiry "$WORK/parse/good.profile.plist" 2>/dev/null || true)"
fi

log "== 2. --deploy-only：候选不合格一律中止且不动现有安装 =="
mkdir -p "$PREFIX"
BEFORE="$(seed_install)"

run_deploy_only() { # candidate
  rm -rf "$DERIVED/Build/Products/Release"
  mkdir -p "$DERIVED/Build/Products/Release"
  if [ -n "$1" ] && [ -d "$1" ]; then
    cp -R "$1" "$DERIVED/Build/Products/Release/$BUNDLE_NAME"
  fi
  bash "$APP_SCRIPT" --deploy-only --prefix "$PREFIX" --derived-data "$DERIVED" \
    --team "$TEAM" >"$OUT" 2>"$ERR"
  printf '%s\n' "$?"
}

if [ "$have_openssl" = "yes" ]; then
  make_app "$WORK/cand-expired.app" --profile "$WORK/parse/expired.profile"
  rc="$(run_deploy_only "$WORK/cand-expired.app")"
  check_is "描述文件已过期的候选：退出码 3" "3" "$rc"
  check_contains "描述文件已过期的候选：说明进程" "过期" "$ERR"
  check_contains "描述文件已过期的候选：现有安装保持不变" "现有安装保持不变" "$ERR"
  check_absent "描述文件已过期的候选：不报成功" "install_biometric_app=ok" "$OUT"
  check_is "描述文件已过期的候选：现有安装字节不变" "$BEFORE" "$(install_fingerprint)"
  check_is "描述文件已过期的候选：没有留下暂存目录" "" \
    "$(find "$PREFIX" -maxdepth 1 -name '.KeyKoi Biometric.app.new.*' -o -maxdepth 1 -name '.KeyKoi Biometric.app.old.*' | tr -d '\n')"

  make_app "$WORK/cand-good-profile.app" --profile "$WORK/parse/good.profile"
  rc="$(run_deploy_only "$WORK/cand-good-profile.app")"
  check_is "签名团队与期望不符的候选：退出码 3" "3" "$rc"
  check_contains "签名团队与期望不符的候选：说明进程" "TeamIdentifier" "$ERR"
  check_is "签名团队与期望不符的候选：现有安装字节不变" "$BEFORE" "$(install_fingerprint)"
fi

make_app "$WORK/cand-unsigned.app" --profile "$WORK/parse/good.profile" --unsigned
rc="$(run_deploy_only "$WORK/cand-unsigned.app")"
check_is "未签名候选：退出码 3" "3" "$rc"
check_contains "未签名候选：codesign 报错原样进 stderr" "codesign" "$ERR"
check_absent "未签名候选：不报成功" "install_biometric_app=ok" "$OUT"
check_is "未签名候选：现有安装字节不变" "$BEFORE" "$(install_fingerprint)"

make_app "$WORK/cand-no-profile.app"
rc="$(run_deploy_only "$WORK/cand-no-profile.app")"
check_is "缺描述文件的候选：退出码 3" "3" "$rc"
check_contains "缺描述文件的候选：说明进程" "embedded.provisionprofile" "$ERR"
check_is "缺描述文件的候选：现有安装字节不变" "$BEFORE" "$(install_fingerprint)"

rc="$(run_deploy_only "")"
check_is "没有构建产物：退出码 2" "2" "$rc"
check_contains "没有构建产物：给出 deploy=no-artifact" "deploy=no-artifact" "$OUT"
check_is "没有构建产物：现有安装字节不变" "$BEFORE" "$(install_fingerprint)"

log "== 3. --build-if-needed：构建脚本报告的不可用产物不会被拿来顶替 =="
cat >"$WORK/stub-build-bad.sh" <<STUB
#!/usr/bin/env bash
# 替身：报告一个「描述文件存在但已经过期」的产物，模拟旧产物顶替的场景。
STATUS=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    --status-file) STATUS="\$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "\$STATUS" ] && { printf 'build=ok\napp=%s\n' "$WORK/cand-expired.app" >"\$STATUS"; }
exit 0
STUB
chmod +x "$WORK/stub-build-bad.sh"
if [ "$have_openssl" = "yes" ]; then
  sha="$(install_fingerprint)"
  env KEYKOI_BIOMETRIC_BUILD_SCRIPT="$WORK/stub-build-bad.sh" \
    bash "$APP_SCRIPT" --build-if-needed --prefix "$PREFIX" --derived-data "$DERIVED" \
    --team "$TEAM" --force-expiry-check >"$OUT" 2>"$ERR"
  rc=$?
  check_is "构建脚本报告过期产物：退出码 3" "3" "$rc"
  check_absent "构建脚本报告过期产物：不报成功" "install_biometric_app=ok" "$OUT"
  check_is "构建脚本报告过期产物：现有安装字节不变" "$sha" "$(install_fingerprint)"
fi

cat >"$WORK/stub-build-fail.sh" <<'STUB'
#!/usr/bin/env bash
# 替身：模拟 Xcode 未登录 / 没有描述文件（build-biometric-app.sh 退出码 3）。
STATUS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --status-file) STATUS="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$STATUS" ] && printf 'build=failed\nfailure_class=profile\n' >"$STATUS"
echo "xcodebuild 失败（exit=65，错误类别：profile）。" >&2
exit 3
STUB
chmod +x "$WORK/stub-build-fail.sh"
sha="$(install_fingerprint)"
env KEYKOI_BIOMETRIC_BUILD_SCRIPT="$WORK/stub-build-fail.sh" \
  bash "$APP_SCRIPT" --build-if-needed --prefix "$PREFIX" --derived-data "$DERIVED" \
  --team "$TEAM" --force-expiry-check >"$OUT" 2>"$ERR"
rc=$?
check_is "构建失败：退出码 2" "2" "$rc"
check_contains "构建失败：报告 manual" "install_biometric_app=manual" "$OUT"
check_contains "构建失败：给出 manual 指引" "manual:" "$ERR"
check_absent "构建失败：不报成功" "install_biometric_app=ok" "$OUT"
check_is "构建失败：现有安装字节不变" "$sha" "$(install_fingerprint)"

log "== 4. 静态断言：状态检查失败不会被当成成功 =="
ok_lines="$(grep -n 'install_biometric_app=ok' "$APP_SCRIPT" | grep -vcE '^[0-9]+:[[:space:]]*#')"
check_is "成功收尾标记只有一处（conclude_after_deploy）" "1" "$ok_lines"
# C locale 下 bash 会把紧跟在变量名后的多字节字符当成变量名的一部分（set -u 直接崩），
# launchd 环境正好没有 LANG，所以这条要一直守住。
if perl -ne 'exit(1) if /\$[A-Za-z_][A-Za-z0-9_]*[^\x00-\x7F]/' "$APP_SCRIPT"; then
  ok "没有「变量名紧跟全角字符」的写法"
else
  bad "没有「变量名紧跟全角字符」的写法"
fi
if sed -n '/^conclude_after_deploy() {/,/^}/p' "$APP_SCRIPT" \
    | grep -q 'install_biometric_app=ok'; then
  ok "成功标记写在 conclude_after_deploy 里"
else
  bad "成功标记写在 conclude_after_deploy 里"
fi
if sed -n '/^conclude_after_deploy() {/,/^}/p' "$APP_SCRIPT" \
    | grep -q 'install_biometric_app=failed'; then
  ok "状态检查不通过时打印 install_biometric_app=failed"
else
  bad "状态检查不通过时打印 install_biometric_app=failed"
fi
conclude_calls="$(grep -c 'conclude_after_deploy "' "$APP_SCRIPT")"
if [ "$conclude_calls" -ge 3 ]; then
  ok "两条部署路径（deploy-only / build-if-needed）都经 conclude_after_deploy 收尾（$conclude_calls 处）"
else
  bad "两条部署路径都经 conclude_after_deploy 收尾" "calls=$conclude_calls"
fi
if grep -q 'status_rc' "$APP_SCRIPT"; then
  ok "状态检查退出码被显式捕获"
else
  bad "状态检查退出码被显式捕获"
fi

log "== 5. 成功路径与替换失败回滚（替身 codesign，不接触真实签名身份） =="
if [ "$have_openssl" = "no" ]; then
  log "SKIP 5（没有可现造的描述文件）"
else
  BIN_OK="$WORK/bin-codesign"
  BIN_MVFAIL="$WORK/bin-mvfail"
  mkdir -p "$BIN_OK" "$BIN_MVFAIL"
  # 替身 codesign：只回答「签名/权限/团队」三个问题，让候选通过校验。
  cat >"$BIN_OK/codesign" <<'STUB'
#!/usr/bin/env bash
team="${SELFCHECK_TEAM:-977QNJU6V6}"
if [ -n "${SELFCHECK_CODESIGN_FAIL_MATCH:-}" ]; then
  for arg in "$@"; do
    case "$arg" in
      *"$SELFCHECK_CODESIGN_FAIL_MATCH"*) exit 1 ;;
    esac
  done
fi
case "$*" in
  *--entitlements*)
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n  <key>keychain-access-groups</key>\n  <array><string>%s.com.keykoi.biometric</string></array>\n</dict>\n</plist>\n' "$team"
    exit 0 ;;
esac
case "$*" in
  -dv*) printf 'Executable=keykoi-biometric\nTeamIdentifier=%s\n' "$team"; exit 0 ;;
esac
exit 0
STUB
  chmod +x "$BIN_OK/codesign"
  cp "$BIN_OK/codesign" "$BIN_MVFAIL/codesign"
  # 替身 mv：只让「暂存目录改名就位」这一步失败，其余仍走真实 mv。
  cat >"$BIN_MVFAIL/mv" <<'STUB'
#!/bin/sh
case "$1" in
  *".app.new."*) exit 1 ;;
esac
exec /bin/mv "$@"
STUB
  chmod +x "$BIN_MVFAIL/mv"

  deploy_with() { # bindir candidate [env...]
    local bindir="$1" cand="$2"; shift 2
    rm -rf "$DERIVED/Build/Products/Release"
    mkdir -p "$DERIVED/Build/Products/Release"
    cp -R "$cand" "$DERIVED/Build/Products/Release/$BUNDLE_NAME"
    env PATH="$bindir:$PATH" SELFCHECK_TEAM="$TEAM" "$@" \
      bash "$APP_SCRIPT" --deploy-only --prefix "$PREFIX" --derived-data "$DERIVED" \
      --team "$TEAM" >"$OUT" 2>"$ERR"
    printf '%s\n' "$?"
  }

  rm -rf "$PREFIX"; mkdir -p "$PREFIX"
  make_app "$WORK/cand-ok.app" --profile "$WORK/parse/good.profile"
  rc="$(deploy_with "$BIN_OK" "$WORK/cand-ok.app")"
  check_is "合格候选：退出码 0" "0" "$rc"
  check_contains "合格候选：报告 deployed_app" "deployed_app=$APP" "$OUT"
  check_contains "合格候选：报告成功" "install_biometric_app=ok" "$OUT"
  check_is "合格候选：.app 已就位" "yes" "$([ -d "$APP" ] && echo yes || echo no)"
  check_is "合格候选：没有暂存/备份残留" "" \
    "$(find "$PREFIX" -maxdepth 1 \( -name '.KeyKoi Biometric.app.new.*' -o -name '.KeyKoi Biometric.app.old.*' \) | tr -d '\n')"

  # 状态检查不通过（描述文件只剩几小时）必须传播为失败，而不是报 ok。
  SOON="$(date -u -v+6H +%Y-%m-%dT%H:%M:%SZ)"
  make_profile "$WORK/parse/soon.profile" "$TEAM" "$TEAM.com.keykoi.biometric" "$SOON"
  make_app "$WORK/cand-soon.app" --profile "$WORK/parse/soon.profile"
  ( cd "$DERIVED/Build/Products/Release" 2>/dev/null && rm -rf "$BUNDLE_NAME" ) || true
  rc="$(deploy_with "$BIN_OK" "$WORK/cand-soon.app")"
  check_is "状态检查不通过：退出码传播为 2" "2" "$rc"
  check_contains "状态检查不通过：报 install_biometric_app=failed" "install_biometric_app=failed" "$OUT"
  check_contains "状态检查不通过：给出 install_biometric_app_rc=2" "install_biometric_app_rc=2" "$OUT"
  check_absent "状态检查不通过：不报 ok" "install_biometric_app=ok" "$OUT"
  check_contains "状态检查不通过：状态里有 renew_needed=yes" "renew_needed=yes" "$OUT"

  # 已有安装 → 成功替换：旧内容被新内容取代，不留备份。
  seed_install >/dev/null
  printf 'old-install\n' >"$APP/Contents/MacOS/marker"
  rc="$(deploy_with "$BIN_OK" "$WORK/cand-ok.app")"
  check_is "成功替换：退出码 0" "0" "$rc"
  check_is "成功替换：旧 marker 已随旧产物移除" "no" \
    "$([ -f "$APP/Contents/MacOS/marker" ] && echo yes || echo no)"
  check_is "成功替换：没有暂存/备份残留" "" \
    "$(find "$PREFIX" -maxdepth 1 \( -name '.KeyKoi Biometric.app.new.*' -o -name '.KeyKoi Biometric.app.old.*' \) | tr -d '\n')"

  # 暂存目录改名就位失败 → 回滚，原安装保持不变。
  seed_install >/dev/null
  BEFORE="$(install_fingerprint)"
  rc="$(deploy_with "$BIN_MVFAIL" "$WORK/cand-ok.app")"
  check_is "改名就位失败：退出码 3" "3" "$rc"
  check_contains "改名就位失败：说明已回滚" "回滚到原安装" "$ERR"
  check_is "改名就位失败：原安装字节不变" "$BEFORE" "$(install_fingerprint)"
  check_absent "改名就位失败：不报成功" "install_biometric_app=ok" "$OUT"

  # 部署后复核失败 → 回滚，原安装保持不变。
  seed_install >/dev/null
  BEFORE="$(install_fingerprint)"
  rc="$(deploy_with "$BIN_OK" "$WORK/cand-ok.app" SELFCHECK_CODESIGN_FAIL_MATCH="$APP")"
  check_is "部署后复核失败：退出码 3" "3" "$rc"
  check_contains "部署后复核失败：说明已回滚" "部署后复核失败" "$ERR"
  check_is "部署后复核失败：原安装字节不变" "$BEFORE" "$(install_fingerprint)"
  check_absent "部署后复核失败：不报成功" "install_biometric_app=ok" "$OUT"
fi

log "== 6. 真实签名产物端到端（本机已有构建产物时） =="
REAL_DERIVED="$ROOT/packaging/macos/biometric-app/build"
REAL_APP="$REAL_DERIVED/Build/Products/Release/$BUNDLE_NAME"
if [ ! -d "$REAL_APP" ]; then
  log "SKIP 6（没有 $REAL_APP，先在 Xcode 里构建一次再跑）"
else
  REAL_PREFIX="$WORK/real-prefix"
  rm -rf "$REAL_PREFIX"; mkdir -p "$REAL_PREFIX"
  bash "$APP_SCRIPT" --deploy-only --prefix "$REAL_PREFIX" --derived-data "$REAL_DERIVED" \
    --team "$TEAM" >"$OUT" 2>"$ERR"
  rc=$?
  check_is "真实产物：首次部署退出码 0" "0" "$rc"
  check_contains "真实产物：签名团队与 --team 一致" "signature_team=$TEAM" "$OUT"
  check_contains "真实产物：报告成功" "install_biometric_app=ok" "$OUT"
  check_is "真实产物：助手可执行就位" "yes" \
    "$([ -x "$REAL_PREFIX/$BUNDLE_NAME/Contents/MacOS/keykoi-biometric" ] && echo yes || echo no)"

  bash "$APP_SCRIPT" --deploy-only --prefix "$REAL_PREFIX" --derived-data "$REAL_DERIVED" \
    --team "$TEAM" >"$OUT" 2>"$ERR"
  check_is "真实产物：重复部署（替换已有安装）退出码 0" "0" "$?"
  check_contains "真实产物：重复部署报告成功" "install_biometric_app=ok" "$OUT"

  REAL_BEFORE="$( cd "$REAL_PREFIX/$BUNDLE_NAME" && find . -type f -exec shasum -a 256 {} + | sort )"
  bash "$APP_SCRIPT" --deploy-only --prefix "$REAL_PREFIX" --derived-data "$REAL_DERIVED" \
    --team ZZZZZZZZZZ >"$OUT" 2>"$ERR"
  rc=$?
  check_is "真实产物 + 错的 --team：退出码 3" "3" "$rc"
  check_contains "真实产物 + 错的 --team：说明团队不一致" "不一致" "$ERR"
  check_absent "真实产物 + 错的 --team：不报成功" "install_biometric_app=ok" "$OUT"
  check_is "真实产物 + 错的 --team：现有安装字节不变" "true" \
    "$([ "$REAL_BEFORE" = "$( cd "$REAL_PREFIX/$BUNDLE_NAME" && find . -type f -exec shasum -a 256 {} + | sort )" ] && echo true || echo false)"

  if [ "$have_openssl" = "yes" ]; then
    # 真实产物换上「已过期」的描述文件：封条会一起失效，但「描述文件过期」这条校验
    # 必须独立报出来并中止，不能拿它顶替当前助手。
    EXP_SRC="$WORK/real-expired"
    rm -rf "$EXP_SRC"; mkdir -p "$EXP_SRC/Build/Products/Release"
    cp -R "$REAL_APP" "$EXP_SRC/Build/Products/Release/"
    [ -f "$WORK/cert.pem" ] || openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$WORK/cert.key" -out "$WORK/cert.pem" -days 2 \
      -subj "/CN=keykoi-selfcheck" >/dev/null 2>&1
    PAST="$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ)"
    make_profile "$EXP_SRC/expired.profile" "$TEAM" "$TEAM.com.keykoi.biometric" "$PAST" "$TEAM.*"
    cp "$EXP_SRC/expired.profile" \
      "$EXP_SRC/Build/Products/Release/$BUNDLE_NAME/Contents/embedded.provisionprofile"
    bash "$APP_SCRIPT" --deploy-only --prefix "$REAL_PREFIX" --derived-data "$EXP_SRC" \
      --team "$TEAM" >"$OUT" 2>"$ERR"
    rc=$?
    check_is "真实签名 + 过期描述文件：退出码 3" "3" "$rc"
    check_contains "真实签名 + 过期描述文件：报出已过期" "已过期" "$ERR"
    check_absent "真实签名 + 过期描述文件：不报成功" "install_biometric_app=ok" "$OUT"
    check_is "真实签名 + 过期描述文件：现有安装字节不变" "true" \
      "$([ "$REAL_BEFORE" = "$( cd "$REAL_PREFIX/$BUNDLE_NAME" && find . -type f -exec shasum -a 256 {} + | sort )" ] && echo true || echo false)"
  fi
fi

log "== 7. 兼容性：帮助与 Keychain 边界 =="
bash "$APP_SCRIPT" --help >"$OUT" 2>"$ERR"
check_is "--help 退出码 0" "0" "$?"
check_contains "--help 仍列出 --deploy-only" "--deploy-only" "$OUT"
check_contains "--help 仍列出 --status 输出约定" "install_biometric_app" "$OUT"
TOUCHES="$(grep -nE '[[:space:]"](store|load|delete)([[:space:]"]|$)|delete-generic-password|add-generic-password' \
  "$APP_SCRIPT" | grep -vE '^\S+:[0-9]+:[[:space:]]*#' || true)"
check_is "安装脚本仍然不调用助手的 store/load/delete" "" "$TOUCHES"

log "== 8. Swift 钥匙串重新登记顺序（静态断言，不触发 Touch ID） =="
STORE_SRC="$WORK/storeRootKey.swift"
awk '/^func storeRootKey\(account: String, root: Data\) throws \{$/ {p=1} p {print} p && /^}$/ {exit}' \
  "$BIOMETRIC_SRC" >"$STORE_SRC"
if [ -s "$STORE_SRC" ]; then
  ok "自检取到了实际 storeRootKey 实现"
else
  bad "自检取到了实际 storeRootKey 实现" "函数缺失或签名已改变"
fi

staging_add_line="$(awk '/let stagingStatus = SecItemAdd/ {print NR; exit}' "$STORE_SRC")"
staging_read_line="$(awk '/try copyRootKey\(account: pendingAccount\(account\), context: context\)/ {print NR; exit}' "$STORE_SRC")"
update_line="$(awk '/let updateStatus = SecItemUpdate/ {print NR; exit}' "$STORE_SRC")"
if [ -n "$staging_add_line" ] && [ -n "$staging_read_line" ] && [ -n "$update_line" ] \
    && [ "$staging_add_line" -lt "$staging_read_line" ] \
    && [ "$staging_read_line" -lt "$update_line" ]; then
  ok "重新登记严格按暂存写入、读回验证、原子更新排序"
else
  bad "重新登记严格按暂存写入、读回验证、原子更新排序" \
    "add=${staging_add_line:-missing} read=${staging_read_line:-missing} update=${update_line:-missing}"
fi
check_contains "读回的新根密钥必须与本次输入逐字节一致" "stagedRoot == root" "$STORE_SRC"
check_contains "暂存项沿用本次创建的生物识别 ACL" \
  "itemQuery(account: pendingAccount(account), attributes: attributes)" "$STORE_SRC"
check_contains "正式项原子更新沿用同一套生物识别 ACL" \
  "SecItemUpdate(updateQuery as CFDictionary, attributes as CFDictionary)" "$STORE_SRC"
check_absent "任何重新登记分支都不删除正式旧项" \
  "SecItemDelete(baseQuery(account: account)" "$STORE_SRC"
check_absent "不再保留撤旧后重写正式项的回退" "let retryStatus = SecItemAdd" "$STORE_SRC"

UNSUPPORTED_SRC="$WORK/unsupported-update.swift"
awk '/case errSecParam, errSecUnimplemented:/ {p=1} p {print} p && /default:/ {exit}' \
  "$STORE_SRC" >"$UNSUPPORTED_SRC"
check_contains "不支持原子更新时明确失败而不是继续撤旧" "throw fail(.unavailable" "$UNSUPPORTED_SRC"
check_contains "不支持原子更新时报告正式旧项未变" \
  "the previously enrolled root key is unchanged" "$UNSUPPORTED_SRC"

log ""
log "通过 $PASSED 项，失败 $FAILED 项。"
if [ "$FAILED" -gt 0 ]; then exit 1; fi
exit 0
