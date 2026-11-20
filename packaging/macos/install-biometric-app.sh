#!/usr/bin/env bash
# 把已签名的 `KeyKoi Biometric.app` 部署到稳定位置，并在需要时自动重建。
#
# 为什么要这一步：Xcode 用 Personal Team（免费 Apple ID）自动签发的
# `Mac Team Provisioning Profile` 只有 7 天有效期（`ExpirationDate` 在
# embedded.provisionprofile 里）。过期后 AMFI 拒绝启动带
# `keychain-access-groups` 的助手，keykoid 会报 AUTH_UNAVAILABLE 并回退主密码。
# 因此部署必须能判断「描述文件还剩几天」，并在临期时重新构建/重新签发。
#
# 用法：
#   bash packaging/macos/install-biometric-app.sh [--build-if-needed|--deploy-only|--status]
# 选项：
#   --build-if-needed     现有 .app 的描述文件剩余 <3 天（或缺失/读不出）时调用
#                         build-biometric-app.sh 重建，然后把产物部署到 prefix。
#                         没有 .app 或描述文件缺失同样视为需要构建。
#                         这是默认行为（不给模式参数时等价）。
#   --deploy-only         只部署 DerivedData 里已有的产品，不检查到期时间、不构建。
#   --status              只打印状态：到期时间、剩余天数、签名团队、签名/权限校验。
#                         不写文件、不构建、不碰 Keychain。
#   --prefix DIR          部署前缀（默认 $KEYKOI_PREFIX 或 ~/Library/Application Support/KeyKoi）
#   --team TEAMID         覆盖开发团队（默认 $KEYKOI_DEV_TEAM 或 977QNJU6V6）
#   --min-days N          剩余天数阈值，低于它就要重建（默认 3）
#   --force-expiry-check  无视剩余天数，强制走一次重建（验收用来模拟临期）
#   --renew-now           立即向 Apple 申请新描述文件，仅在有效期推进后替换
#   --background          临期续签失败且不足一天时发送一次系统通知
#   --derived-data DIR    构建产物目录（默认沿用 build-biometric-app.sh 的默认值）
#   --log FILE            把本脚本的输出追加到 FILE（LaunchAgent 用）
#   --print-exe           只输出部署后的助手可执行文件路径
#   -h|--help             显示本帮助
#
# 输出约定：机器可读的 key=value 打到 stdout，人读摘要打到 stderr；两侧内容一致。
#   app / app_exists / profile_expiry / profile_expiry_epoch / remaining_seconds
#   remaining_days / renew_needed / signature_team / codesign_verify
#   entitlements_keychain_access_groups / helper / helper_env
#   deployed_app / install_biometric_app=ok|failed|manual|unavailable
#   install_biometric_app_rc（状态检查不通过时给出它的退出码）
#
# 退出码：
#   0  已部署且描述文件仍在有效期内
#   2  需要人工：构建失败（Xcode 未登录/无 Keychain Sharing/无描述文件/网络）、
#      没有可用构建产物；或部署完成后状态检查不通过（原样传播状态检查的退出码）
#   3  候选产物校验失败（codesign / keychain-access-groups / 描述文件过期或
#      TeamID、App ID 与 --team 不一致）或部署后复核失败，原安装保持不变
#   5  环境不可用（非 macOS 或缺少 xcodebuild）
#
# 部署顺序（缺陷 32）：候选 .app 先复制到 prefix 下的暂存目录 → 校验候选的签名、
# 权限与描述文件（到期时间、TeamID、App ID 全部与 --team 一致才算可用）→ 旧产物
# 与暂存目录原子交换 → 复核新产物 → 最后清理暂存里的旧产物。失败时保留可恢复的原安装。
# 状态检查（report_status）的失败一律传播为脚本失败，不会「检查失败仍报成功」。
# 这里沿用 set -uo pipefail 而不是 set -e：大量探测命令（security/codesign/plutil）
# 本来就允许失败，失败分支要逐条判断，所以靠显式 exit 传播退出码。
#
# 边界：本脚本只做「构建 → 复制 → 签名校验 → 报告」。不调用助手的
# store/load/delete，不写、不改、不删任何 Keychain 条目。
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# LaunchAgent / env -i 下 HOME 可能根本不存在（set -u 会直接炸），先兜底。
if [ -z "${HOME:-}" ] || [ ! -d "${HOME:-/nonexistent}" ]; then
  HOME="$(dscl . -read "/Users/$(id -un)" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
  [ -n "$HOME" ] || HOME="$(eval echo "~$(id -un)")"
  export HOME
fi
BUNDLE_NAME="KeyKoi Biometric.app"
EXE_NAME="keykoi-biometric"
# 描述文件里的 App ID / keychain-access-groups 必须以 <TEAM>.<BUNDLE_ID> 结尾，
# AMFI 才认这份授权；部署前的候选校验用它对期望值。
BUNDLE_ID="com.keykoi.biometric"
# KEYKOI_BIOMETRIC_BUILD_SCRIPT 只给验收用：注入一个替身构建脚本以覆盖失败分支，
# 正常运行不要设置。
BUILD_SCRIPT="${KEYKOI_BIOMETRIC_BUILD_SCRIPT:-$DIR/build-biometric-app.sh}"
DEFAULT_DERIVED="$DIR/biometric-app/build"
DEFAULT_PREFIX="$HOME/Library/Application Support/KeyKoi"

TEAM="${KEYKOI_DEV_TEAM:-977QNJU6V6}"
PREFIX="${KEYKOI_PREFIX:-$DEFAULT_PREFIX}"
MIN_DAYS="${KEYKOI_BIOMETRIC_RENEW_DAYS:-3}"
MODE=""
FORCE_EXPIRY_CHECK=0
RENEW_NOW=0
BACKGROUND=0
SUPERSEDED_CACHE=""
DERIVED=""
LOG_FILE=""
PRINT_EXE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --build-if-needed) MODE="build-if-needed"; shift ;;
    --deploy-only) MODE="deploy-only"; shift ;;
    --status) MODE="status"; shift ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --team) TEAM="$2"; shift 2 ;;
    --min-days) MIN_DAYS="$2"; shift 2 ;;
    --force-expiry-check) FORCE_EXPIRY_CHECK=1; shift ;;
    --renew-now) MODE="build-if-needed"; RENEW_NOW=1; shift ;;
    --background) BACKGROUND=1; shift ;;
    --derived-data) DERIVED="$2"; shift 2 ;;
    --log) LOG_FILE="$2"; shift 2 ;;
    --print-exe) PRINT_EXE=1; shift ;;
    # 帮助取「第二行到 set 行」的文件头注释，头部增删行不会错位。
    -h|--help) sed -n '2,/^set /p' "$0" | sed -e '/^set /d' -e 's/^#\{1,\} \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 5 ;;
  esac
done
[ -n "$MODE" ] || MODE="build-if-needed"
[ -n "$DERIVED" ] || DERIVED="$DEFAULT_DERIVED"

APP="$PREFIX/$BUNDLE_NAME"
PROFILE="$APP/Contents/embedded.provisionprofile"
EXE="$APP/Contents/MacOS/$EXE_NAME"

# LaunchAgent 下的输出必须落盘才可见。
if [ -n "$LOG_FILE" ]; then
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  exec > >(tee -a "$LOG_FILE") 2>&1
fi

say() { printf '%s\n' "$*"; }
note() { printf '%s\n' "$*" >&2; }
machine() { say "$1"; note "$2"; }

# launchd 里 HOME/PATH 可能缺项：xcodebuild 自动签名要访问登录钥匙串里的
# Apple Development 身份和 Xcode 的账户缓存，这些都挂在真实 HOME 下。
ensure_env() {
  if [ -z "${HOME:-}" ] || [ ! -d "${HOME:-/nonexistent}" ]; then
    local real_home
    real_home="$(dscl . -read "/Users/$(id -un)" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    [ -n "$real_home" ] || real_home="$(eval echo "~$(id -un)")"
    export HOME="$real_home"
  fi
  local dev
  dev="${DEVELOPER_DIR:-$(xcode-select -p 2>/dev/null || true)}"
  if [ -n "$dev" ] && [ -d "$dev" ]; then
    export DEVELOPER_DIR="$dev"
    case ":$PATH:" in
      *":$dev/usr/bin:"*) : ;;
      *) export PATH="$dev/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin${PATH:+:$PATH}" ;;
    esac
  else
    case ":$PATH:" in
      *":/usr/bin:"*) : ;;
      *) export PATH="/usr/bin:/bin:/usr/sbin:/sbin${PATH:+:$PATH}" ;;
    esac
  fi
  export KEYKOI_DEV_TEAM="$TEAM"
}

# 从嵌入的描述文件里读一个字段（plutil 的 keypath），读不出输出空并返回非零。
# 只在探测用，失败原因由调用方给出，所以这里静音探测命令的 stderr。
profile_field() { # profile keypath
  local value
  value="$(security cms -D -i "$1" 2>/dev/null | plutil -extract "$2" raw -o - - 2>/dev/null)"
  [ -n "${value:-}" ] || return 1
  printf '%s\n' "$value"
}

# 描述文件声明的团队：TeamIdentifier 是数组，plutil 取 json 后剥掉方括号/引号。
profile_team() { # profile
  security cms -D -i "$1" 2>/dev/null \
    | plutil -extract TeamIdentifier json -o - - 2>/dev/null \
    | sed -e 's/^\[//' -e 's/\]$//' -e 's/"//g' -e 's/,.*//' \
      -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# 描述文件授权的 App ID（形如 <TEAM>.<BUNDLE_ID>）。
# 这个键名里本身带点（com.apple.application-identifier），plutil 的 keypath 会把点当
# 分隔符而读不到，所以走 plutil -p 的文本输出再取这一行。
profile_app_id() { # profile
  security cms -D -i "$1" 2>/dev/null \
    | plutil -p - 2>/dev/null \
    | sed -n 's/^[[:space:]]*"com\.apple\.application-identifier" => "\(.*\)"$/\1/p' \
    | head -1
}

# 描述文件允许的 keychain-access-groups，剥成逗号分隔的裸列表。
# 实测 Mac Team Provisioning Profile 给的是通配 <TEAM>.*，不是具体的 <TEAM>.<bundle>。
profile_access_groups() { # profile
  security cms -D -i "$1" 2>/dev/null \
    | plutil -extract "Entitlements.keychain-access-groups" json -o - - 2>/dev/null \
    | tr -d '[]"\n\r\t '
}

# 签名里实际声明的访问组（形如 <TEAM>.<BUNDLE_ID>）。
signed_access_group() { # bundle
  codesign -d --entitlements :- "$1" 2>/dev/null \
    | plutil -extract keychain-access-groups.0 raw -o - - 2>/dev/null
}

# 读 embedded.provisionprofile 的 ExpirationDate。
# 输出 "<原始值>\t<epoch>"；读不出返回 1。
read_expiry() { # profile
  local raw norm epoch
  raw="$(profile_field "$1" ExpirationDate)" || return 1
  [ -n "${raw:-}" ] || return 1
  norm="${raw%Z}"
  norm="${norm/T/ }"
  # plutil raw 给 2026-11-26T17:13:46Z；plutil -p 给 2026-11-26 17:13:46 +0000。
  epoch="$(date -j -u -f "%Y-%m-%d %H:%M:%S" "$norm" +%s 2>/dev/null)"
  [ -n "${epoch:-}" ] || return 1
  printf '%s\t%s\n' "$raw" "$epoch"
}

signature_team() { # bundle
  codesign -dv --verbose=4 "$1" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -1
}

codesign_state() { # bundle → ok|failed
  if codesign --verify --strict "$1" >/dev/null 2>&1; then echo ok; else echo failed; fi
}

entitlements_state() { # bundle → yes|no
  local ents
  ents="$(codesign -d --entitlements :- "$1" 2>/dev/null || true)"
  case "$ents" in
    *keychain-access-groups*) echo yes ;;
    *) echo no ;;
  esac
}

now_epoch() { date +%s; }

# 计算剩余秒/天数，写成全局变量。
REMAINING_SECONDS=""
REMAINING_DAYS=""
EXPIRY_RAW=""
EXPIRY_EPOCH=""
compute_remaining() { # profile
  local line
  line="$(read_expiry "$1")" || return 1
  EXPIRY_RAW="${line%%$'\t'*}"
  EXPIRY_EPOCH="${line##*$'\t'}"
  REMAINING_SECONDS=$(( EXPIRY_EPOCH - $(now_epoch) ))
  REMAINING_DAYS="$(awk -v s="$REMAINING_SECONDS" 'BEGIN{printf "%.1f", s/86400}')"
  return 0
}

min_seconds() { awk -v d="$MIN_DAYS" 'BEGIN{printf "%d", d*86400}'; }

# 描述文件剩余秒数（负数表示已过期）。不写全局变量，供候选校验单独用。
profile_remaining_seconds() { # profile
  local line
  line="$(read_expiry "$1")" || return 1
  printf '%s\n' "$(( ${line##*$'\t'} - $(now_epoch) ))"
}

report_status() { # exit_code_for_callers? -> prints status, returns 0/2
  local app_exists=no verify=none group=no team="" loaded
  [ -d "$APP" ] && app_exists=yes
  verify="$(codesign_state "$APP")"
  [ -d "$APP" ] && group="$(entitlements_state "$APP")"
  [ -d "$APP" ] && team="$(signature_team "$APP")"

  local renew_needed=no reason=""
  if [ "$app_exists" != "yes" ]; then
    renew_needed=yes; reason="app-missing"
  elif [ ! -f "$PROFILE" ]; then
    renew_needed=yes; reason="profile-missing"
  elif ! compute_remaining "$PROFILE"; then
    renew_needed=yes; reason="profile-unreadable"
  elif [ "$REMAINING_SECONDS" -lt "$(min_seconds)" ]; then
    renew_needed=yes; reason="expiring"
  fi
  if [ "$app_exists" = "yes" ] && { [ "$verify" != "ok" ] || [ "$group" != "yes" ] || [ "$team" != "$TEAM" ]; }; then
    renew_needed=yes; reason="${reason:-invalid-signature}"
  fi

  machine "app=$APP" "app: $APP"
  machine "app_exists=$app_exists" "exists: $app_exists"
  machine "helper=$EXE" "helper: $EXE"
  machine "helper_env=KEYKOI_BIOMETRIC_HELPER=$EXE" "export KEYKOI_BIOMETRIC_HELPER=\"$EXE\""
  machine "prefix=$PREFIX" "prefix: $PREFIX"
  machine "signature_team=${team:-unknown}" "signature team: ${team:-unknown}"
  machine "codesign_verify=$verify" "codesign --verify --strict: $verify"
  machine "entitlements_keychain_access_groups=$group" "keychain-access-groups: $group"
  if [ -n "${EXPIRY_RAW:-}" ]; then
    machine "profile_expiry=$EXPIRY_RAW" "profile expires at: $EXPIRY_RAW"
    machine "profile_expiry_epoch=$EXPIRY_EPOCH" "profile expires (epoch): $EXPIRY_EPOCH"
    machine "remaining_seconds=$REMAINING_SECONDS" "remaining: $REMAINING_SECONDS s"
    machine "remaining_days=$REMAINING_DAYS" "remaining: $REMAINING_DAYS 天"
  else
    machine "profile_expiry=none" "profile expires at: (读不到：$( [ -f "$PROFILE" ] && echo 文件存在但解析失败 || echo 描述文件缺失 ))"
    machine "profile_expiry_epoch=0" "profile expires (epoch): 0"
    machine "remaining_seconds=0" "remaining: 0 s"
    machine "remaining_days=0.0" "remaining: 0.0 天"
  fi
  machine "min_days=$MIN_DAYS" "renew threshold: <$MIN_DAYS 天"
  machine "renew_needed=$renew_needed" "renew needed: $renew_needed${reason:+ ($reason)}"
  machine "renew_reason=${reason:-none}" "renew reason: ${reason:-none}"

  if [ "$renew_needed" = "yes" ]; then return 2; fi
  return 0
}

# 候选/已部署产物的完整校验（部署前与替换后共用）。只有全绿才返回 0：
#   1) codesign --verify --deep --strict 通过（报错原样打到 stderr，不吞 stderr）
#   2) 签名含 keychain-access-groups
#   3) 可执行文件存在且可执行
#   4) embedded.provisionprofile 存在、能解析、未过期
#   5) 描述文件的 TeamIdentifier、签名 TeamIdentifier 与 --team 一致
#   6) 描述文件授权的 App ID 为 <TEAM>.<BUNDLE_ID>，且 keychain-access-groups 含该组
# 任何一项失败都视为「不可用」，调用方据此中止，不改动现有安装。
verify_deployed() { # dir
  local app="$1" profile team sig_team app_id group_value profile_groups remaining detail errs=0
  profile="$app/Contents/embedded.provisionprofile"

  if [ ! -d "$app" ]; then
    note "校验失败：没有目录 $app"
    return 1
  fi

  if ! detail="$(codesign --verify --deep --strict "$app" 2>&1)"; then
    note "校验失败：$(basename "$app") 未通过 codesign --verify --deep --strict"
    printf '%s\n' "$detail" | sed 's/^/  /' >&2
    errs=$((errs+1))
  fi

  if [ "$(entitlements_state "$app")" != "yes" ]; then
    note "校验失败：$(basename "$app") 签名里没有 keychain-access-groups"
    errs=$((errs+1))
  fi

  if [ ! -x "$app/Contents/MacOS/$EXE_NAME" ]; then
    note "校验失败：缺少可执行文件 $app/Contents/MacOS/$EXE_NAME"
    errs=$((errs+1))
  fi

  if [ ! -f "$profile" ]; then
    note "校验失败：缺少 ${profile}（没有描述文件授权，助手会被 AMFI 拒绝启动）"
    return 1
  fi

  if ! remaining="$(profile_remaining_seconds "$profile")"; then
    note "校验失败：读不出 $profile 的 ExpirationDate（描述文件损坏或不是 provisioning profile）"
    errs=$((errs+1))
  elif [ "$remaining" -le 0 ]; then
    note "校验失败：描述文件已过期（剩余 ${remaining} 秒），不能拿它顶替当前助手"
    errs=$((errs+1))
  fi

  team="$(profile_team "$profile")"
  if [ -z "$team" ]; then
    note "校验失败：描述文件里读不出 TeamIdentifier"
    errs=$((errs+1))
  elif [ "$team" != "$TEAM" ]; then
    note "校验失败：描述文件的 TeamIdentifier=$team 与期望团队 $TEAM 不一致"
    errs=$((errs+1))
  fi

  sig_team="$(signature_team "$app")"
  if [ "$sig_team" != "$TEAM" ]; then
    note "校验失败：签名 TeamIdentifier=${sig_team:-none} 与期望团队 $TEAM 不一致"
    errs=$((errs+1))
  fi

  app_id="$(profile_app_id "$profile")"
  if [ -z "$app_id" ]; then
    note "校验失败：描述文件里读不出 Entitlements.com.apple.application-identifier"
    errs=$((errs+1))
  else
    # 具体 App ID 或该团队的通配 App ID 都接受，但都必须属于期望团队。
    case "$app_id" in
      "$TEAM.$BUNDLE_ID"|"$TEAM.*") : ;;
      *) note "校验失败：描述文件授权的 App ID=$app_id 不是 $TEAM.$BUNDLE_ID"
         errs=$((errs+1)) ;;
    esac
  fi

  # 签名里的访问组必须被描述文件授权：描述文件可能写具体值，也可能写 <TEAM>.*。
  group_value="$(signed_access_group "$app")"
  if [ -z "$group_value" ]; then
    note "校验失败：签名里读不出 keychain-access-groups 的值"
    errs=$((errs+1))
  else
    case "$group_value" in
      "$TEAM.$BUNDLE_ID") : ;;
      *) note "校验失败：签名的访问组 $group_value 与 $TEAM.$BUNDLE_ID 不一致"
         errs=$((errs+1)) ;;
    esac
    profile_groups="$(profile_access_groups "$profile")"
    case ",${profile_groups}," in
      *",$group_value,"*) : ;;
      *",$TEAM.*,"*) : ;;
      *) note "校验失败：描述文件没有授权签名里的访问组 ${group_value}（描述文件里是 ${profile_groups:-none}）"
         errs=$((errs+1)) ;;
    esac
  fi

  [ "$errs" -eq 0 ]
}

swap_apps() {
  # macOS renamex_np(RENAME_SWAP) exchanges two bundles without a missing-path interval.
  /usr/bin/python3 - "$1" "$2" <<'PY'
import ctypes
import os
import sys

rename = ctypes.CDLL(None, use_errno=True).renamex_np
rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
if rename(os.fsencode(sys.argv[1]), os.fsencode(sys.argv[2]), 0x00000002):
    raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
PY
}

# 部署顺序（缺陷 32）：暂存写入 → 校验候选 → 原子替换 → 复核 → 清理旧状态。
# 每一步失败都保留原安装（$APP 保持不变或回滚回来），绝不用「描述文件还在的旧
# 产物」顶替当前助手，也不允许出现「旧产物已删、新产物未就位」的空档。
deploy_from() { # source_app description [minimum_expiry_epoch]
  local src="$1" label="$2" minimum_expiry="${3:-0}" staging had_app=no candidate
  [ -d "$src" ] || { note "没有找到构建产物：$src"; return 2; }
  mkdir -p "$PREFIX" || { note "无法创建 $PREFIX"; return 3; }

  # 1) 先复制到同前缀下的暂存目录：现有安装此时一个字节都没动。
  staging="$PREFIX/.${BUNDLE_NAME}.new.$$"
  rm -rf "$staging"
  if ! ditto "$src" "$staging"; then
    note "复制失败：$src → $staging"
    rm -rf "$staging"
    return 3
  fi

  # 2) 候选自身必须完整可用（签名 + 权限 + 描述文件有效期/TeamID/App ID）。
  if ! verify_deployed "$staging"; then
    note "候选产物校验不通过：${staging}；现有安装保持不变"
    rm -rf "$staging"
    return 3
  fi
  if [ "$minimum_expiry" -gt 0 ]; then
    candidate="$(read_expiry "$staging/Contents/embedded.provisionprofile")" || { rm -rf "$staging"; return 3; }
    if [ "${candidate##*$'\t'}" -le "$minimum_expiry" ]; then
      rm -rf "$staging"
      machine "renew_result=profile-not-extended" "Apple 尚未签发有效期更长的描述文件；保留现有助手，下次检查再试。"
      return 2
    fi
  fi

  if [ -e "$APP" ]; then
    had_app=yes
    if ! swap_apps "$APP" "$staging"; then
      note "无法原子替换助手，保留现有安装。"
      rm -rf "$staging"
      return 3
    fi
  elif ! mv "$staging" "$APP"; then
    rm -rf "$staging"
    return 3
  fi

  # 4) 新产物就位后复核一次；不通过则回滚，旧产物此时还在。
  if ! verify_deployed "$APP"; then
    note "部署后复核失败：回滚到原安装"
    if [ "$had_app" = yes ]; then
      if ! swap_apps "$APP" "$staging"; then
        note "回滚失败：旧助手保存在 $staging"
        return 3
      fi
    else
      rm -rf "$APP"
    fi
    rm -rf "$staging"
    return 3
  fi

  # 5) 最后才清理旧状态。
  rm -rf "$staging"
  machine "deployed_app=$APP" "deployed $label → $APP"
  return 0
}

manual_note() { # context
  note ""
  note "manual: 自动续签没有完成（$1）。"
  note "  1) 确认已登录 Xcode → Settings… → Accounts（团队 $TEAM 可用）；"
  note "  2) 确认 com.keykoi.biometric 勾选了 Keychain Sharing 能力；"
  note "  3) 手动重建：bash $BUILD_SCRIPT --team $TEAM"
  note "  4) 再部署：bash $DIR/install-biometric-app.sh --deploy-only --prefix \"$PREFIX\""
  note "  也可以一条命令重来：bash $DIR/install-biometric-app.sh --build-if-needed --prefix \"$PREFIX\""
  note "  免费 Personal Team 的描述文件有效期上限就是 7 天，续签靠重签而不是延期；"
  note "  见 docs/指南/生物识别助手续签与部署.md 的付费账号方案（1 年）。"
}

run_build() {
  local status_file rc class
  status_file="$(mktemp "${TMPDIR:-/tmp}/keykoi-biometric-build.XXXXXX")"
  note "构建中：bash $BUILD_SCRIPT --team $TEAM --derived-data $DERIVED --no-probe"
  # --no-probe：LaunchAgent 里没有 GUI 会话，available 会返回 unavailable；
  # 续签只依赖签名/权限/描述文件这三项校验。
  bash "$BUILD_SCRIPT" --team "$TEAM" --derived-data "$DERIVED" \
    --no-probe --status-file "$status_file" >/dev/null
  rc=$?
  class="$(sed -n 's/^failure_class=//p' "$status_file" 2>/dev/null | head -1)"
  BUILT_APP="$(sed -n 's/^app=//p' "$status_file" 2>/dev/null | head -1)"
  machine "build_exit=$rc" "build exit: $rc${class:+ (class=$class)}"
  if [ "$rc" -ne 0 ]; then
    rm -f "$status_file"
    manual_note "构建退出码 $rc${class:+，错误类别 $class}"
    return 2
  fi
  rm -f "$status_file"
  if [ -z "${BUILT_APP:-}" ] || [ ! -d "$BUILT_APP" ]; then
    manual_note "构建脚本没有报告产物路径"
    return 2
  fi
  return 0
}

renew_build() {
  local uuid cache saved rc=0
  uuid="$(profile_field "$PROFILE" UUID)" || { run_build; return $?; }
  case "$uuid" in *[!0-9a-fA-F-]*|'') run_build; return $? ;; esac
  cache="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles/$uuid.provisionprofile"
  [ -f "$cache" ] || cache="$HOME/Library/MobileDevice/Provisioning Profiles/$uuid.provisionprofile"
  if ! cmp -s "$PROFILE" "$cache"; then run_build; return $?; fi
  saved="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-profile.XXXXXX")" || return 2
  if ! mv "$cache" "$saved/installed.provisionprofile"; then rmdir "$saved"; return 2; fi
  # Refresh only the byte-identical cache entry. The installed bundle keeps its own profile.
  restore_cached_profile() {
    if [ ! -e "$cache" ]; then
      mv "$saved/installed.provisionprofile" "$cache" || return 1
    else
      rm -f "$saved/installed.provisionprofile"
    fi
    rmdir "$saved"
  }
  trap 'restore_cached_profile' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  run_build || rc=$?
  restore_cached_profile || note "原缓存保存在 $saved/installed.provisionprofile"
  trap - EXIT INT TERM
  if [ "$rc" -eq 0 ] && [ "$(profile_field "$cache" UUID)" = "$uuid" ] &&
      [ "$(profile_field "$cache" ExpirationDate)" = "$EXPIRY_RAW" ]; then
    SUPERSEDED_CACHE="$cache"
  fi
  return "$rc"
}

notify_renewal_problem() {
  [ "$BACKGROUND" = 1 ] && [ -n "$EXPIRY_EPOCH" ] && [ "$REMAINING_SECONDS" -le 86400 ] || return 0
  local notice="$PREFIX/data/biometric-renew-alerted"
  [ "$(cat "$notice" 2>/dev/null)" != "$EXPIRY_EPOCH" ] || return 0
  if /usr/bin/osascript -e 'display notification "请检查 Xcode 的 Apple 账户登录。Touch ID 到期后可用主密码解锁。" with title "KeyKoi Touch ID 续签待处理"' >/dev/null 2>&1; then
    printf '%s\n' "$EXPIRY_EPOCH" > "$notice"
  fi
}

# 部署后的统一收尾：report_status 打全套状态，并把它的退出码原样传播出去。
# 检查不通过时不再打印 install_biometric_app=ok —— 安装结果必须反映真实状态，
# 不能「检查失败仍报成功」（缺陷 32 的第二半）。
conclude_after_deploy() { # mode_label
  local label="$1" status_rc=0
  report_status || status_rc=$?
  if [ "$PRINT_EXE" = "1" ]; then say "$EXE"; fi
  machine "mode=$label" "mode: $label"
  if [ "$status_rc" -ne 0 ]; then
    note "状态检查未通过（退出码 ${status_rc}）：已部署的产物保持原样，但这次安装按失败上报；"
    note "  具体原因见上面的 renew_reason / profile_expiry / codesign_verify 行。"
    machine "install_biometric_app=failed" "install_biometric_app=failed"
    machine "install_biometric_app_rc=$status_rc" "install_biometric_app_rc: $status_rc"
    return "$status_rc"
  fi
  machine "install_biometric_app=ok" "install_biometric_app=ok"
  return 0
}

DRY_CHECK_ONLY=0
if [ "$MODE" = "status" ]; then
  report_status
  rc=$?
  machine "mode=status" "mode: status"
  exit "$rc"
fi

if [ "$MODE" = "deploy-only" ]; then
  SRC="$DERIVED/Build/Products/Release/$BUNDLE_NAME"
  if [ ! -d "$SRC" ]; then
    note "没有可部署的构建产物：$SRC"
    manual_note "DerivedData 里没有 $BUNDLE_NAME"
    machine "mode=deploy-only" "mode: deploy-only (no artifact)"
    machine "deploy=no-artifact" "deploy: no-artifact"
    exit 2
  fi
  deploy_from "$SRC" "DerivedData 产物" || exit $?
  conclude_after_deploy "deploy-only"
  exit $?
fi

# --build-if-needed（默认）
if [ "$(uname -s)" != "Darwin" ]; then
  note "skip: 生物识别 .app 只能在 macOS 上构建/部署（当前 $(uname -s)）。"
  machine "mode=build-if-needed" "mode: build-if-needed"
  machine "install_biometric_app=unavailable" "install_biometric_app=unavailable"
  exit 5
fi

ensure_env

NEED=no
if [ ! -d "$APP" ] || [ ! -f "$PROFILE" ]; then
  NEED=yes
elif ! compute_remaining "$PROFILE"; then
  NEED=yes
elif [ "$REMAINING_SECONDS" -lt "$(min_seconds)" ]; then
  NEED=yes
fi
if [ "$FORCE_EXPIRY_CHECK" = "1" ] || [ "$RENEW_NOW" = "1" ]; then NEED=yes; fi

if [ "$NEED" = "yes" ]; then
  if [ -n "${EXPIRY_RAW:-}" ]; then
    note "描述文件到期 ${EXPIRY_RAW}（剩余 ${REMAINING_DAYS} 天，阈值 ${MIN_DAYS} 天）→ 重建"
  else
    note "没有可用的 KeyKoi Biometric.app / 描述文件 → 构建"
  fi
  minimum_expiry=0
  if [ -n "$REMAINING_SECONDS" ] && [ "$REMAINING_SECONDS" -gt 0 ] &&
      { [ "$RENEW_NOW" = "1" ] || [ "$REMAINING_SECONDS" -lt "$(min_seconds)" ]; } && verify_deployed "$APP"; then
    minimum_expiry="$EXPIRY_EPOCH"
    renew_build || { machine "install_biometric_app=manual" "install_biometric_app=manual"; notify_renewal_problem; exit 2; }
  else
    run_build || { machine "install_biometric_app=manual" "install_biometric_app=manual"; notify_renewal_problem; exit 2; }
  fi
  deploy_from "$BUILT_APP" "新构建的 .app" "$minimum_expiry" || {
    rc=$?
    machine "install_biometric_app=failed" "本次未部署新助手，下次检查再试。"
    notify_renewal_problem
    exit "$rc"
  }
  if [ -n "$SUPERSEDED_CACHE" ]; then
    archive="$PREFIX/data/biometric-profiles"
    if (umask 077; mkdir -p "$archive") && [ ! -e "$archive/${SUPERSEDED_CACHE##*/}" ]; then
      mv "$SUPERSEDED_CACHE" "$archive/" || note "旧描述文件仍在 Xcode 缓存，下一次检查会再次尝试续签。"
    fi
  fi
  # 状态同时进日志：续签日志里要能看到新的到期时间；退出码跟状态一致。
  conclude_after_deploy "build-if-needed"
  exit $?
fi

# 现有 app 还新鲜：先确认它本身是完整可用的（签名 + 描述文件有效期/团队/App ID）。
if verify_deployed "$APP"; then
  note "描述文件仍有效（剩余 ${REMAINING_DAYS} 天），跳过构建"
  conclude_after_deploy "build-if-needed"
  exit $?
fi

note "现有 .app 校验不通过 → 重建"
run_build || { machine "install_biometric_app=manual" "install_biometric_app=manual"; exit 2; }
deploy_from "$BUILT_APP" "重建的 .app" || exit $?
conclude_after_deploy "build-if-needed"
exit $?
