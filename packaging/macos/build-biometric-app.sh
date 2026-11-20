#!/usr/bin/env bash
# 把生物识别助手（packaging/macos/keykoi-biometric.swift）打进一个已签名的
# `.app` 包，并输出可执行文件路径给 keykoi / keykoid 使用。
#
# 为什么要 .app：`keychain-access-groups` 是受限权限，裸二进制即使签名也会被
# AMFI 在启动阶段杀死（见 packaging/macos/sign-biometric.sh 的 launch_probe）。
# 装进 .app 后系统才会读 Contents/embedded.provisionprofile，权限才有描述文件
# 授权；keykoid 直接执行 Contents/MacOS/keykoi-biometric，不经过 LaunchServices。
#
# 用法：
#   bash packaging/macos/build-biometric-app.sh [选项]
# 选项：
#   --team TEAMID       开发团队（默认 $KEYKOI_DEV_TEAM 或 977QNJU6V6）
#   --configuration C   Release（默认）或 Debug
#   --derived-data DIR  DerivedData 目录（默认 packaging/macos/biometric-app/build）
#   --install-dir DIR   构建校验通过后把 .app 复制到 DIR（如 ~/Applications）
#   --print-path        只输出可执行文件绝对路径（给脚本用）
#   --no-probe          跳过启动探测（只做签名/权限/描述文件校验）
#   --status-file PATH  把结果写成一个 key=value 文件（供验收脚本读取）
#   -h|--help           显示本帮助
#
# 退出码：
#   0  构建、签名、校验、启动探测全部通过
#   2  需要人工准备：Xcode 未登录 Apple ID / 团队不支持 Keychain Sharing /
#      没有可用描述文件（错误信息里给出对应步骤）
#   3  xcodebuild 构建失败（编译或链接问题）
#   4  构建成功但校验失败（签名、keychain-access-groups、描述文件或启动探测）
#   5  当前环境无法构建（非 macOS 或缺少 Xcode 命令行工具）
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
APP_PROJECT_DIR="$DIR/biometric-app"
PROJECT="$APP_PROJECT_DIR/KeyKoiBiometric.xcodeproj"
SCHEME="KeyKoiBiometric"
BUNDLE_NAME="KeyKoi Biometric.app"
EXE_NAME="keykoi-biometric"
BUNDLE_ID="com.keykoi.biometric"

TEAM="${KEYKOI_DEV_TEAM:-977QNJU6V6}"
CONFIG="Release"
DERIVED="${KEYKOI_BIOMETRIC_DERIVED_DATA:-$APP_PROJECT_DIR/build}"
INSTALL_DIR=""
PRINT_PATH_ONLY=0
NO_PROBE=0
STATUS_FILE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --team) TEAM="$2"; shift 2 ;;
    --configuration) CONFIG="$2"; shift 2 ;;
    --derived-data) DERIVED="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --print-path) PRINT_PATH_ONLY=1; shift ;;
    --no-probe) NO_PROBE=1; shift ;;
    --status-file) STATUS_FILE="$2"; shift 2 ;;
    -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 5 ;;
  esac
done

say() { printf '%s\n' "$*"; }
note() { printf '%s\n' "$*" >&2; }

STATUS=()
status() { STATUS+=("$1=$2"); }

finish() { # code
  if [ -n "$STATUS_FILE" ]; then
    mkdir -p "$(dirname "$STATUS_FILE")"
    : >"$STATUS_FILE"
    for line in "${STATUS[@]:-}"; do
      [ -n "$line" ] && printf '%s\n' "$line" >>"$STATUS_FILE"
    done
  fi
  exit "$1"
}

manual_help() { # class
  case "$1" in
    apple-id)
      note ""
      note "原因：Xcode 没有登录 Apple ID（或者该团队在本机不可用）。"
      note "处理：打开 Xcode → Settings… → Accounts，添加 Apple ID 并选中团队；"
      note "      Xcode → Settings… → Accounts → Manage Certificates… → + → Apple Development，"
      note "      确认 Keychain Access 里出现 “Apple Development: <你的 Apple ID>”。"
      note "      登录后重跑：bash packaging/macos/build-biometric-app.sh"
      ;;
    keychain-sharing)
      note ""
      note "原因：该 App ID / 团队没有启用 Keychain Sharing 能力，自动签名无法签发"
      note "      带 keychain-access-groups 的描述文件。"
      note "处理：developer.apple.com → Certificates, Identifiers & Profiles → Identifiers →"
      note "      com.keykoi.biometric → 勾选 Keychain Sharing → Save；"
      note "      免费的 Personal Team 若看不到该能力，需要用付费开发者账号（或换团队）。"
      note "      然后重跑：bash packaging/macos/build-biometric-app.sh"
      ;;
    profile)
      note ""
      note "原因：没有可用的描述文件（自动签名没能创建或下载 Mac Team Provisioning Profile）。"
      note "处理：确认 Xcode 已登录、团队有效、网络可达 developer.apple.com，然后重跑："
      note "      bash packaging/macos/build-biometric-app.sh"
      note "      仍失败时在 Xcode 里手动打开 biometric-app/KeyKoiBiometric.xcodeproj，"
      note "      勾选 Automatically manage signing 让它生成一次描述文件。"
      ;;
    network)
      note ""
      note "原因：与 Apple 开发者服务通信失败（自动签名需要联网获取描述文件）。"
      note "处理：确认网络/代理可用后重跑本脚本。"
      ;;
  esac
}

if [ "$(uname -s)" != "Darwin" ]; then
  note "skip: 生物识别 .app 只能在 macOS 上构建（当前 $(uname -s)）。"
  status build "skipped"
  finish 5
fi
if ! command -v xcodebuild >/dev/null 2>&1; then
  note "缺少 xcodebuild：先安装 Xcode（App Store）并执行 sudo xcode-select -s /Applications/Xcode.app。"
  status build "no-xcodebuild"
  finish 5
fi
if ! command -v python3 >/dev/null 2>&1; then
  note "缺少 python3：本机没有 xcodegen，工程文件由 Tools/generate-xcodeproj.py 生成。"
  status build "no-python3"
  finish 5
fi

# 工程文件缺失或显式要求时重新生成（生成是确定性的，不会产生噪声 diff）。
if [ ! -f "$PROJECT/project.pbxproj" ] || [ "${KEYKOI_REGEN_XCODEPROJ:-0}" = "1" ]; then
  python3 "$APP_PROJECT_DIR/Tools/generate-xcodeproj.py" >/dev/null || {
    note "生成 Xcode 工程失败：$APP_PROJECT_DIR/Tools/generate-xcodeproj.py"
    status build "project-generation-failed"
    finish 3
  }
fi

mkdir -p "$DERIVED"
LOG="$DERIVED/xcodebuild.log"

# 预检查只用于把失败原因说清楚，最终仍以 xcodebuild 的真实结果为准。
ACCOUNTS="$(defaults read com.apple.dt.Xcode IDEProvisioningTeamByIdentifier 2>/dev/null || true)"
TEAM_REGISTERED="no"
if printf '%s' "$ACCOUNTS" | grep -q "$TEAM"; then TEAM_REGISTERED="yes"; fi
IDENTITIES="$(security find-identity -v -p codesigning 2>/dev/null || true)"
HAS_IDENTITY="no"
if printf '%s' "$IDENTITIES" | grep -q "Apple Development"; then HAS_IDENTITY="yes"; fi

status team "$TEAM"
status team_registered_in_xcode "$TEAM_REGISTERED"
status signing_identity_present "$HAS_IDENTITY"

if [ "$PRINT_PATH_ONLY" != "1" ]; then
  say "project:     $PROJECT"
  say "team:        $TEAM (Xcode 已登记团队: $TEAM_REGISTERED, Apple Development 身份: $HAS_IDENTITY)"
  say "configuration: $CONFIG"
  say "derived_data:$DERIVED"
  say "building..."
fi

set +e
xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration "$CONFIG" \
  -derivedDataPath "$DERIVED" \
  -allowProvisioningUpdates \
  DEVELOPMENT_TEAM="$TEAM" \
  CODE_SIGN_STYLE=Automatic \
  build >"$LOG" 2>&1
BUILD_CODE=$?
set -e

if [ "$BUILD_CODE" -ne 0 ]; then
  CLASS="build-failed"
  if grep -qE "There are no accounts registered with Xcode|No Account for Team|No signing certificate|Signing for .* requires a development team" "$LOG"; then
    CLASS="apple-id"
  elif grep -qiE "does(n't| not) support the Keychain Sharing capability|does not include the keychain-access-groups entitlement|Keychain Sharing" "$LOG"; then
    CLASS="keychain-sharing"
  elif grep -qiE "No profiles for '?$BUNDLE_ID'?|There is no provisioning profile|no matching provisioning profiles|doesn't include signing certificate" "$LOG"; then
    CLASS="profile"
  elif grep -qiE "Communication with Apple|NSURLErrorDomain|The network connection was lost|timed out" "$LOG"; then
    CLASS="network"
  fi
  note "xcodebuild 失败（exit=${BUILD_CODE}，错误类别：${CLASS}）。日志：$LOG"
  status build "failed"
  status failure_class "$CLASS"
  grep -E "error:|error " "$LOG" | head -8 | sed 's/^/  /' >&2
  manual_help "$CLASS"
  finish 3
fi

APP="$DERIVED/Build/Products/$CONFIG/$BUNDLE_NAME"
EXE="$APP/Contents/MacOS/$EXE_NAME"
PROFILE="$APP/Contents/embedded.provisionprofile"

fail_validation() { # detail
  note "校验失败：$1"
  note "日志：$LOG"
  status validate "failed"
  status failure_detail "$1"
  finish 4
}

[ -d "$APP" ] || fail_validation "没有找到构建产物 $APP"
[ -x "$EXE" ] || fail_validation "缺少可执行文件 $EXE"
[ -f "$PROFILE" ] || fail_validation "缺少嵌入式描述文件 ${PROFILE}（没有描述文件授权，keychain-access-groups 会被 AMFI 拒绝）"

CODESIGN_VERIFY="failed"
if codesign --verify --strict "$APP" >/dev/null 2>&1; then CODESIGN_VERIFY="ok"; fi
[ "$CODESIGN_VERIFY" = "ok" ] || fail_validation "codesign --verify --strict 不通过"

SIGNED_ENTS="$(codesign -d --entitlements :- "$APP" 2>/dev/null || true)"
HAS_GROUP="no"
if printf '%s' "$SIGNED_ENTS" | grep -q "keychain-access-groups"; then HAS_GROUP="yes"; fi
[ "$HAS_GROUP" = "yes" ] || fail_validation "签名里没有 keychain-access-groups"

GROUP_VALUE="$(printf '%s' "$SIGNED_ENTS" \
  | tr '<' '\n' | sed -n 's/^string>\(.*com\.keykoi\.biometric\)$/\1/p' | head -1)"
SIGNATURE_TEAM="$(codesign -dv --verbose=4 "$APP" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -1)"
case "$GROUP_VALUE" in
  "$SIGNATURE_TEAM".*) : ;;
  *) fail_validation "keychain-access-groups 的值 ($GROUP_VALUE) 与签名团队 ($SIGNATURE_TEAM) 不匹配" ;;
esac

PROFILE_STATE="absent"
PROFILE_DECODED="$(security cms -D -i "$PROFILE" 2>/dev/null || true)"
if [ -n "$PROFILE_DECODED" ]; then
  if printf '%s' "$PROFILE_DECODED" | grep -q "keychain-access-groups"; then
    if printf '%s' "$PROFILE_DECODED" | grep -q "$TEAM"; then
      PROFILE_STATE="authorizes-keychain-access-groups"
    else
      PROFILE_STATE="present-without-team"
    fi
  else
    PROFILE_STATE="present-without-entitlement"
  fi
fi
if [ "$PROFILE_STATE" != "authorizes-keychain-access-groups" ]; then
  manual_help keychain-sharing
  fail_validation "描述文件状态为 ${PROFILE_STATE}，没有授权 ${TEAM} 的 keychain-access-groups"
fi

PLIST_CHECK="$(plutil -p "$APP/Contents/Info.plist" 2>/dev/null || true)"
case "$PLIST_CHECK" in
  *'"LSUIElement" => 1'*|*'"LSUIElement" => true'*) LSUI_ELEMENT="yes" ;;
  *) LSUI_ELEMENT="no" ;;
esac

LAUNCH="ok"
LAUNCH_DETAIL=""
if [ "$NO_PROBE" != "1" ]; then
  PROBE_OUT="$("$EXE" available 2>&1)"
  PROBE_CODE=$?
  case "$PROBE_CODE" in
    0) LAUNCH="ok" ;;
    2) LAUNCH="no-biometry"; LAUNCH_DETAIL="$PROBE_OUT" ;;
    3) LAUNCH="cancelled"; LAUNCH_DETAIL="$PROBE_OUT" ;;
    4) LAUNCH="unavailable"; LAUNCH_DETAIL="$PROBE_OUT" ;;
    137|139) LAUNCH="killed-on-launch"; LAUNCH_DETAIL="$PROBE_OUT" ;;
    *) LAUNCH="failed"; LAUNCH_DETAIL="$PROBE_OUT" ;;
  esac
fi

if [ -n "$INSTALL_DIR" ]; then
  mkdir -p "$INSTALL_DIR"
  rm -rf "$INSTALL_DIR/$BUNDLE_NAME"
  ditto "$APP" "$INSTALL_DIR/$BUNDLE_NAME"
  INSTALLED="$INSTALL_DIR/$BUNDLE_NAME/Contents/MacOS/$EXE_NAME"
  status installed_app "$INSTALL_DIR/$BUNDLE_NAME"
else
  INSTALLED=""
fi

status build "ok"
status app "$APP"
status exe "$EXE"
status bundle_id "$BUNDLE_ID"
status signature_team "$SIGNATURE_TEAM"
status keychain_access_group "$GROUP_VALUE"
status entitlements_keychain_access_groups "$HAS_GROUP"
status codesign_verify "$CODESIGN_VERIFY"
status embedded_profile "$PROFILE_STATE"
status profile_uuid "$(printf '%s' "$PROFILE_DECODED" | plutil -extract UUID raw -o - - 2>/dev/null || echo unknown)"
status lsui_element "$LSUI_ELEMENT"
status launch_probe "$LAUNCH"
[ -n "$INSTALLED" ] && status installed_exe "$INSTALLED"

if [ "$PRINT_PATH_ONLY" = "1" ]; then
  if [ -n "$INSTALLED" ]; then say "$INSTALLED"; else say "$EXE"; fi
  if [ "$LAUNCH" = "ok" ] || [ "$NO_PROBE" = "1" ]; then finish 0; fi
  finish 4
fi

say ""
say "app:               $APP"
say "executable:        $EXE"
say "bundle_id:         $BUNDLE_ID"
say "signature_team:    ${SIGNATURE_TEAM:-unknown}"
say "keychain_access_group: $GROUP_VALUE"
say "entitlements_keychain_access_groups=$HAS_GROUP"
say "codesign_verify=$CODESIGN_VERIFY"
say "embedded_profile=$PROFILE_STATE"
say "lsui_element=$LSUI_ELEMENT"
say "launch_probe=$LAUNCH${LAUNCH_DETAIL:+ ($LAUNCH_DETAIL)}"
if [ -n "$INSTALLED" ]; then
  say "installed:         $INSTALLED"
fi
say ""
say "让 keykoi / keykoid 使用这个助手："
say "  export KEYKOI_BIOMETRIC_HELPER=\"${INSTALLED:-$EXE}\""
say "  keykoi vault enroll-biometric   # 首次登记会弹 Touch ID"
say "  keykoi unlock --biometric"
say "KEYKOI_BIOMETRIC_HELPER=${INSTALLED:-$EXE}"

case "$LAUNCH" in
  ok)
    say ""
    say "note: store/load 仍然要经过系统生物识别；真实指纹确认（enroll + unlock）是人工步骤。"
    finish 0
    ;;
  no-biometry)
    say ""
    say "manual: 本机没有已登记的 Touch ID/Optic ID（或指纹被锁定）。录入指纹后重跑。"
    finish 0
    ;;
  *)
    note "启动探测未通过（$LAUNCH${LAUNCH_DETAIL:+：$LAUNCH_DETAIL}）。"
    note "签名与描述文件校验通过但助手不能启动时，请检查系统日志："
    note "  log show --last 5m --predicate 'eventMessage CONTAINS \"keykoi-biometric\"'"
    finish 4
    ;;
esac
