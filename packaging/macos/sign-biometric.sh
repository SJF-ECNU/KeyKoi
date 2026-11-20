#!/usr/bin/env bash
# 给 Touch ID 助手（keykoi-biometric）签名并校验 keychain-access-groups 权限。
#
# 背景：生物的 Keychain 条目使用 ACL `biometryCurrentSet`，只有带
# `keychain-access-groups` 权限的签名二进制才能创建它。裸编译产物会被系统以
# errSecMissingEntitlement(-34018) 拒绝，因此需要一次真实签名。
#
# 用法：
#   bash packaging/macos/sign-biometric.sh [选项] [HELPER]
# 选项：
#   --helper PATH     要签名的助手（默认 packaging/macos/keykoi-biometric）
#   --identity NAME   指定签名身份（默认从 security find-identity 自动挑选）
#   --team TEAMID     覆盖从证书取到的团队 ID（entitlements 里的 TEAMID 前缀）
#   --provision PATH  描述文件（默认找同目录 embedded.provisionprofile
#                     或 ${KEYKOI_PROVISIONPROFILE}）
#   --keep-signed     即使助手在启动探测中被系统杀掉，也保留签名后的文件
#   -h|--help         显示本帮助
#
# 退出码：
#   0  已签名且校验通过（keychain-access-groups 在签名里）
#   2  找不到可用的 Apple Development / Developer ID 签名身份（需要人工准备）
#   3  签名失败
#   4  签名后校验失败（缺少 keychain-access-groups 或 codesign --verify 不通过）
#
# 说明：即使签名通过，把 `keychain-access-groups` 用在裸二进制上时 macOS 仍会在
# 启动阶段杀死进程（AMFI 要求该权限由描述文件授权）。脚本因此会做一次
# `available` 启动探测：探测失败的默认行为是回滚到签名前的文件并把签名结果留在
# `<helper>.signed`，避免装上一个起不来的助手。真实 Touch ID 登记（Keychain
# Sharing 能力 + 描述文件 + 指纹确认）仍是人工步骤。
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
HELPER="$DIR/keykoi-biometric"
ENTITLEMENTS="$DIR/keykoi-biometric.entitlements"
IDENTITY=""
TEAM=""
PROVISION="${KEYKOI_PROVISIONPROFILE:-}"
KEEP_SIGNED=0

while [ $# -gt 0 ]; do
  case "$1" in
    --helper) HELPER="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --team) TEAM="$2"; shift 2 ;;
    --provision) PROVISION="$2"; shift 2 ;;
    --keep-signed) KEEP_SIGNED=1; shift ;;
    -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) HELPER="$1"; shift ;;
  esac
done

say() { printf '%s\n' "$*"; }
note() { printf '%s\n' "$*" >&2; }

if [ -z "$PROVISION" ] && [ -f "$DIR/embedded.provisionprofile" ]; then
  PROVISION="$DIR/embedded.provisionprofile"
fi

# 找不到签名身份时给出的明确指引：这是最常见的失败原因。
no_identity_help() {
  note "没有找到可用的 Apple Development / Developer ID 签名身份。"
  note ""
  note "手动准备签名身份（需要 Apple ID，免费账号也可以做开发签名）："
  note "  1. 打开 Xcode → Settings… → Accounts，用 Apple ID 登录。"
  note "  2. 选中该 Apple ID → Manage Certificates… → 左下角 + → Apple Development，"
  note "     证书会写进登录钥匙串（Keychain Access 里能看到 “Apple Development: <你的 Apple ID>”）。"
  note "  3. 在 Xcode → Settings… → Accounts → 团队列表里确认团队存在；"
  note "     没有团队时在 developer.apple.com 用同一 Apple ID 创建个人团队（免费）。"
  note "  4. 给这个 App ID 打开 Keychain Sharing 能力（Xcode → target → Signing & Capabilities"
  note "     → + Capability → Keychain Sharing），下载描述文件后放到本目录"
  note "     embedded.provisionprofile，或设置 KEYKOI_PROVISIONPROFILE=<路径>。"
  note ""
  note "完成后重跑：bash packaging/macos/sign-biometric.sh"
  note "在此之前生物识别仍可用（available 正常），但根密钥无法写入 Keychain，"
  note "keykoid 会用主密码回退并报告 AUTH_UNAVAILABLE。"
  exit 2
}

if [ "$(uname -s)" != "Darwin" ]; then
  note "skip: 生物识别助手签名只在 macOS 上有意义（当前 $(uname -s)）。"
  no_identity_help
fi

if ! command -v security >/dev/null 2>&1 || ! command -v codesign >/dev/null 2>&1; then
  note "skip: 缺少 security / codesign 命令。"
  no_identity_help
fi

if [ ! -f "$HELPER" ]; then
  note "找不到助手：$HELPER"
  note "先编译：bash packaging/macos/build-biometric.sh \"$HELPER\""
  exit 3
fi
if [ ! -f "$ENTITLEMENTS" ]; then
  note "找不到权限文件：$ENTITLEMENTS"
  exit 3
fi

IDENTITIES="$(security find-identity -v -p codesigning 2>/dev/null || true)"

if [ -z "$IDENTITY" ]; then
  for pattern in "Developer ID Application" "Apple Development" "Apple Distribution" "Mac Developer"; do
    IDENTITY="$(printf '%s\n' "$IDENTITIES" | sed -n "s/.*\"\(${pattern}: [^\"]*\)\".*/\1/p" | head -1)"
    [ -n "$IDENTITY" ] && break
  done
fi

if [ -z "$IDENTITY" ]; then
  note "security find-identity -v -p codesigning 返回："
  if [ -z "$IDENTITIES" ]; then
    note "  (没有任何有效的代码签名身份)"
  else
    printf '%s\n' "$IDENTITIES" | sed 's/^/  /' >&2
  fi
  no_identity_help
fi

# 团队 ID 取自证书的 OU；entitlements 里的 TEAMID 前缀要用它替换。
if [ -z "$TEAM" ] && command -v openssl >/dev/null 2>&1; then
  TEAM="$(security find-certificate -c "$IDENTITY" -p 2>/dev/null \
    | openssl x509 -noout -subject -nameopt multiline 2>/dev/null \
    | sed -n 's/.*organizationalUnitName *= *//p' | tr -d ' ' | head -1)"
fi
if [ -z "$TEAM" ]; then
  TEAM="TEAMID"
  note "note: 没能从证书里取到团队 ID，保留 TEAMID 占位（可用 --team 指定）。"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-sign.XXXXXX")"
RENDERED="$WORK/keykoi-biometric.entitlements"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

sed "s/TEAMID/${TEAM}/g" "$ENTITLEMENTS" >"$RENDERED"

say "helper:      $HELPER"
say "identity:    $IDENTITY"
say "team:        $TEAM"
say "entitlements:${RENDERED}（由 ${ENTITLEMENTS} 渲染）"

PROFILE_STATE="absent"
PROFILE_NOTE="-"
if [ -n "$PROVISION" ] && [ -f "$PROVISION" ]; then
  DECODED="$WORK/profile.plist"
  if security cms -D -i "$PROVISION" >"$DECODED" 2>/dev/null; then
    if grep -q "keychain-access-groups" "$DECODED"; then
      if grep -q "${TEAM}" "$DECODED"; then
        PROFILE_STATE="authorizes-keychain-access-groups"
      else
        PROFILE_STATE="present-without-it"
      fi
    else
      PROFILE_STATE="present-without-it"
    fi
    # 只有 .app 包（<bundle>/Contents/MacOS/<exe>）里的描述文件才会被系统采用。
    case "$HELPER" in
      */Contents/MacOS/*)
        BUNDLE="${HELPER%/Contents/MacOS/*}"
        cp "$PROVISION" "$BUNDLE/Contents/embedded.provisionprofile"
        PROFILE_NOTE="embedded into $BUNDLE/Contents/embedded.provisionprofile"
        ;;
      *)
        PROFILE_NOTE="裸二进制不接受描述文件；需要 .app 包才会被系统采用"
        ;;
    esac
  else
    PROFILE_STATE="unreadable"
  fi
fi
say "provision:   ${PROFILE_STATE} ${PROVISION:-（无）}"
say "profile_note:$PROFILE_NOTE"

# 保留签名前的文件，签名在 AMFI 层不可用时可以回滚。
BACKUP="$HELPER.pre-sign"
cp -p "$HELPER" "$BACKUP"

SIGN_LOG="$(codesign --force --options runtime --entitlements "$RENDERED" --sign "$IDENTITY" "$HELPER" 2>&1)"
SIGN_CODE=$?
if [ "$SIGN_CODE" -ne 0 ]; then
  note "签名失败（codesign 退出码 ${SIGN_CODE}）："
  printf '%s\n' "$SIGN_LOG" | sed 's/^/  /' >&2
  cp -p "$BACKUP" "$HELPER"
  exit 3
fi

SIGNED_ENTS="$(codesign -d --entitlements :- "$HELPER" 2>/dev/null)"
VERIFY_LOG="$(codesign --verify --strict --verbose=2 "$HELPER" 2>&1)"
VERIFY_CODE=$?
TEAM_IN_SIG="$(codesign -dv --verbose=4 "$HELPER" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -1)"

HAS_KEYCHAIN="no"
if printf '%s' "$SIGNED_ENTS" | grep -q "keychain-access-groups"; then
  HAS_KEYCHAIN="yes"
fi
say "entitlements_keychain_access_groups=$HAS_KEYCHAIN"
say "signature_team=${TEAM_IN_SIG:-unknown}"
say "codesign_verify=$([ "$VERIFY_CODE" -eq 0 ] && echo ok || echo failed)"
if printf '%s' "$SIGNED_ENTS" | grep -q "keychain-access-groups"; then
  say "signed_entitlements:"
  printf '%s\n' "$SIGNED_ENTS" | sed 's/></>\n</g' | sed 's/^/  /'
fi

if [ "$VERIFY_CODE" -ne 0 ] || [ "$HAS_KEYCHAIN" != "yes" ]; then
  note "校验失败：签名里没有 keychain-access-groups，或 codesign --verify 不通过。"
  printf '%s\n' "$VERIFY_LOG" | sed 's/^/  /' >&2
  cp -p "$BACKUP" "$HELPER"
  exit 4
fi

# 启动探测：带 keychain-access-groups 的裸二进制在缺少描述文件授权时会被
# AMFI 直接杀掉（信号 9）。这时装上去只会让 available 也失效，需要回滚。
probe_launch() {
  local out code
  out="$("$HELPER" available 2>&1)"
  code=$?
  launch_code=$code
  launch_out="$out"
}

launch_code=0
launch_out=""
probe_launch
LAUNCH="ok"
if [ "$launch_code" -ne 0 ]; then
  LAUNCH="blocked"
  if [ "$launch_code" -eq 137 ] || [ "$launch_code" -eq 139 ]; then
    LAUNCH="blocked-by-amfi"
  fi
fi
say "launch_probe=$LAUNCH (exit=$launch_code${launch_out:+, $launch_out})"

if [ "$LAUNCH" = "ok" ]; then
  rm -f "$BACKUP"
  say "deploy=signed"
  say "manual: 真实 Touch ID 需要在交互会话里确认一次指纹（keykoi vault enroll-biometric 后 keykoi unlock --biometric）。"
  exit 0
fi

note "签名成功，但助手在启动探测里没有正常运行（${LAUNCH}）。"
note "原因：keychain-access-groups 属于受限权限，必须先由描述文件授权；"
note "裸二进制的签名在没有对应描述文件时会被 AMFI 在启动阶段杀死。"
note "处理方式：在 Xcode 里给 App ID 打开 Keychain Sharing 能力，用带描述文件的"
note ".app 包分发助手，再重跑本脚本。"
if [ "$KEEP_SIGNED" = "1" ]; then
  say "deploy=blocked-kept-signed（--keep-signed）"
  say "manual: 装上描述文件授权的 .app 包后重跑；在此之前 Touch ID 不可用。"
  exit 0
fi

cp -p "$HELPER" "$HELPER.signed"
cp -p "$BACKUP" "$HELPER"
rm -f "$BACKUP"
say "deploy=reverted（签名结果留在 $HELPER.signed）"
say "manual: 在 Xcode 里为 App ID 打开 Keychain Sharing、生成描述文件后重新签名并安装。"
exit 0
