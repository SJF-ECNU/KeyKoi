#!/usr/bin/env bash
# 用 LaunchAgent 每天检查 `KeyKoi Biometric.app` 的描述文件。
#
# 背景：免费 Apple ID（Personal Team）签发的描述文件只有 7 天有效期，过期后
# AMFI 会拒绝启动带 `keychain-access-groups` 的助手，keykoid 报 AUTH_UNAVAILABLE。
# 本脚本安装一个 `com.keykoi.biometric-renew` 代理，每天及登录时运行
# `install-biometric-app.sh --build-if-needed`：临期才重建（xcodebuild
# -allowProvisioningUpdates 需要联网向 Apple 重新签发描述文件），不临期只写日志。
#
# 用法：
#   bash packaging/macos/install-biometric-renew.sh [--install|--uninstall|--status|--run-now]
# 选项：
#   --install        生成并加载 LaunchAgent（默认动作）
#   --uninstall      卸载 LaunchAgent 并删除 plist（保留日志）
#   --status         打印 plist 路径、是否已加载、schedule、日志位置、下次触发时间
#   --run-now        立即触发一次并检查结果，不中断已经开始的任务
#   --prefix DIR     部署前缀（默认 $KEYKOI_PREFIX 或 ~/Library/Application Support/KeyKoi）
#   --label LABEL    LaunchAgent 标签（默认 com.keykoi.biometric-renew）
#   --weekday N      可选的每周调度，1=周日 … 7=周六（默认每日）
#   --hour N         触发小时（默认 3）
#   --minute N       触发分钟（默认 17）
#   --team TEAMID    传给 install-biometric-app.sh 的团队（默认 $KEYKOI_DEV_TEAM 或 977QNJU6V6）
#   --plist-dir DIR  plist 目录（默认 ~/Library/LaunchAgents；验收用临时目录，避免写用户配置）
#   --no-load        只写 plist，不 bootstrap（给验收/手工检查语法用）
#   -h|--help        显示本帮助
#
# 退出码：
#   0  成功
#   2  launchctl 操作失败、续签未完成或等待超时
#   5  环境不可用（非 macOS）
#
# launchd 环境说明：代理运行时不会加载 shell 启动文件，HOME/PATH/DEVELOPER_DIR
# 都可能缺失。xcodebuild 自动签名要读真实 HOME 下的登录钥匙串（Apple Development
# 身份）与 Xcode 账户缓存，所以 plist 的 EnvironmentVariables 里显式写入
# HOME、PATH（含 Xcode 的 Developer/usr/bin）、DEVELOPER_DIR、KEYKOI_DEV_TEAM；
# install-biometric-app.sh 自己也会兜底解析 HOME 与 DEVELOPER_DIR。
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
APP_SCRIPT="$DIR/install-biometric-app.sh"
BUNDLE_NAME="KeyKoi Biometric.app"
LABEL="com.keykoi.biometric-renew"
PREFIX="${KEYKOI_PREFIX:-$HOME/Library/Application Support/KeyKoi}"
TEAM="${KEYKOI_DEV_TEAM:-977QNJU6V6}"
WEEKDAY=""
HOUR=3
MINUTE=17
ACTION="install"
DO_LOAD=1

while [ $# -gt 0 ]; do
  case "$1" in
    --install) ACTION="install"; shift ;;
    --uninstall) ACTION="uninstall"; shift ;;
    --status) ACTION="status"; shift ;;
    --run-now) ACTION="run-now"; shift ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --weekday) WEEKDAY="$2"; shift 2 ;;
    --hour) HOUR="$2"; shift 2 ;;
    --minute) MINUTE="$2"; shift 2 ;;
    --team) TEAM="$2"; shift 2 ;;
    --plist-dir) PLIST_DIR="$2"; shift 2 ;;
    --no-load) DO_LOAD=0; shift ;;
    -h|--help) sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 5 ;;
  esac
done
case "$WEEKDAY" in
  ""|[1-7]) ;;
  *) echo "--weekday 须在 1 至 7 之间" >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*"; }
note() { printf '%s\n' "$*" >&2; }
machine() { say "$1"; note "$2"; }

UID_NUM="$(id -u)"
PLIST_DIR="${PLIST_DIR:-$HOME/Library/LaunchAgents}"
PLIST="$PLIST_DIR/$LABEL.plist"
LOG="$PREFIX/data/biometric-renew.log"
DOMAIN="gui/$UID_NUM"

is_loaded() { launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1; }

weekday_name() {
  case "$1" in
    1) echo 周日 ;; 2) echo 周一 ;; 3) echo 周二 ;; 4) echo 周三 ;;
    5) echo 周四 ;; 6) echo 周五 ;; 7) echo 周六 ;;
    *) echo "weekday-$1" ;;
  esac
}

if [ "$(uname -s)" != "Darwin" ]; then
  note "skip: LaunchAgent 续签只能在 macOS 上安装（当前 $(uname -s)）。"
  exit 5
fi

case "$ACTION" in
  status)
    machine "label=$LABEL" "label: $LABEL"
    machine "plist=$PLIST" "plist: $PLIST"
    machine "plist_dir=$PLIST_DIR" "plist dir: $PLIST_DIR"
    machine "plist_exists=$([ -f "$PLIST" ] && echo yes || echo no)" "plist exists: $([ -f "$PLIST" ] && echo yes || echo no)"
    machine "loaded=$(is_loaded && echo yes || echo no)" "loaded: $(is_loaded && echo yes || echo no)"
    machine "app_script=$APP_SCRIPT" "app script: $APP_SCRIPT"
    machine "log=$LOG" "log: $LOG"
    machine "log_exists=$([ -f "$LOG" ] && echo yes || echo no)" "log exists: $([ -f "$LOG" ] && echo yes || echo no)"
    NEXT="unknown"
    if [ -f "$PLIST" ]; then
      # launchctl print 不打印 StartCalendarInterval 的下次触发时间，按 plist 自己算。
      NEXT="$(python3 - "$PLIST" <<'PYNEXT'
import datetime, plistlib, sys

with open(sys.argv[1], "rb") as handle:
    body = plistlib.load(handle)
sched = body.get("StartCalendarInterval") or {}
weekday = sched.get("Weekday")
hour = int(sched.get("Hour", 0))
minute = int(sched.get("Minute", 0))
py_weekday = None if weekday is None else (int(weekday) - 1) % 7
now = datetime.datetime.now()
for offset in range(8):
    day = (now + datetime.timedelta(days=offset)).date()
    if py_weekday is None or day.weekday() == py_weekday:
        candidate = datetime.datetime.combine(day, datetime.time(hour, minute))
        if candidate > now:
            print(candidate.strftime("%Y-%m-%d %H:%M"))
            break
else:
    print("unknown")
PYNEXT
)"
      minute="$(plutil -extract StartCalendarInterval.Minute raw -o - "$PLIST")"
      hour="$(plutil -extract StartCalendarInterval.Hour raw -o - "$PLIST")"
      weekday="$(plutil -extract StartCalendarInterval.Weekday raw -o - "$PLIST" 2>/dev/null || true)"
      day="每天"
      [ -z "$weekday" ] || day="每$(weekday_name "$((weekday % 7 + 1))")"
      machine "schedule=weekday=${weekday:-daily} hour=$hour minute=$minute" "已安装调度：$day $(printf '%02d:%02d' "$hour" "$minute")"
    fi
    machine "next_fire=$NEXT" "next fire: $NEXT"
    exit 0
    ;;

  uninstall)
    if is_loaded; then
      if launchctl bootout "$DOMAIN/$LABEL" >/dev/null 2>&1; then
        machine "bootout=ok" "已卸载 $LABEL"
      else
        note "launchctl bootout 失败（${LABEL}），继续删 plist"
        machine "bootout=failed" "bootout 失败"
      fi
    else
      machine "bootout=not-loaded" "$LABEL 本来没有加载"
    fi
    if [ -f "$PLIST" ]; then
      rm -f "$PLIST"
      machine "removed=$PLIST" "已删除 $PLIST"
    else
      machine "removed=none" "没有 $PLIST"
    fi
    machine "log_kept=$LOG" "日志保留在 $LOG"
    exit 0
    ;;
esac

if [ "$ACTION" = "run-now" ]; then
  if ! is_loaded; then
    note "$LABEL 没有加载，先执行 --install"
    exit 2
  fi
  BEFORE=0
  [ -f "$LOG" ] && BEFORE="$(wc -l <"$LOG" | tr -d ' ')"
  if ! launchctl kickstart "$DOMAIN/$LABEL" >/dev/null 2>&1; then
    note "launchctl kickstart 失败"
    exit 2
  fi
  machine "kickstart=ok" "已触发 ${LABEL}，等待 install-biometric-app.sh 收尾标记..."
  # install-biometric-app.sh 末尾总会打 install_biometric_app=ok|manual|unavailable。
  deadline=$(( $(date +%s) + 600 ))
  result="timeout"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ -f "$LOG" ]; then
      tail -n +"$((BEFORE + 1))" "$LOG" 2>/dev/null | grep -q '^install_biometric_app=' && {
        result="$(tail -n +"$((BEFORE + 1))" "$LOG" | sed -n 's/^install_biometric_app=//p' | tail -1)"
        break
      }
    fi
    sleep 1
  done
  machine "run_result=$result" "run result: ${result}（日志 ${LOG}）"
  if [ "$result" = "ok" ]; then exit 0; fi
  exit 2
fi

if [ ! -f "$APP_SCRIPT" ]; then
  note "缺少 $APP_SCRIPT"
  exit 2
fi
if [ ! -x "$APP_SCRIPT" ]; then chmod +x "$APP_SCRIPT" 2>/dev/null || true; fi

mkdir -p "$(dirname "$PLIST")" "$PREFIX/data" 2>/dev/null || true
chmod 700 "$PREFIX/data" 2>/dev/null || true

DEV="${DEVELOPER_DIR:-$(xcode-select -p 2>/dev/null || echo /Applications/Xcode.app/Contents/Developer)}"
REAL_HOME="$HOME"
if [ -z "${REAL_HOME:-}" ] || [ ! -d "$REAL_HOME" ]; then
  REAL_HOME="$(dscl . -read "/Users/$(id -un)" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
fi

# 用 python3 写 plist：避免 here-doc 里的路径含空格/& 时破坏 XML。
python3 - "$PLIST" <<PY
import plistlib, sys

label = "$LABEL"
dev = "$DEV"
home = "$REAL_HOME"
prefix = "$PREFIX"
team = "$TEAM"
log = "$LOG"
app_script = "$APP_SCRIPT"

calendar = {"Hour": int("$HOUR"), "Minute": int("$MINUTE")}
if "$WEEKDAY":
    calendar["Weekday"] = int("$WEEKDAY") - 1

body = {
    "Label": label,
    "ProgramArguments": [
        "/bin/bash",
        app_script,
        "--build-if-needed",
        "--background",
        "--prefix",
        prefix,
        "--team",
        team,
    ],
    "EnvironmentVariables": {
        "HOME": home,
        "PATH": dev + "/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "DEVELOPER_DIR": dev,
        "KEYKOI_DEV_TEAM": team,
        "KEYKOI_PREFIX": prefix,
    },
    "StartCalendarInterval": calendar,
    "RunAtLoad": True,
    "ProcessType": "Background",
    "StandardOutPath": log,
    "StandardErrorPath": log,
    "Umask": 63,
}
with open(sys.argv[1], "wb") as handle:
    plistlib.dump(body, handle, fmt=plistlib.FMT_XML, sort_keys=False)
PY
PLIST_RC=$?
if [ "$PLIST_RC" -ne 0 ]; then
  note "写 plist 失败：$PLIST"
  exit 2
fi
chmod 600 "$PLIST"

LINT="$(plutil -lint "$PLIST" 2>&1)"
LINT_RC=$?
machine "plist=$PLIST" "plist: $PLIST"
machine "plist_lint=$([ "$LINT_RC" -eq 0 ] && echo ok || echo failed)" "plutil -lint: $LINT"

if [ "$DO_LOAD" = "1" ]; then
  launchctl bootout "$DOMAIN/$LABEL" >/dev/null 2>&1 || true
  # bootout 是异步的：立刻 bootstrap 会拿到 EIO，等标签真正消失再加载。
  for _ in $(seq 1 50); do
    is_loaded || break
    sleep 0.1
  done
  ok=0
  for _ in $(seq 1 10); do
    if launchctl bootstrap "$DOMAIN" "$PLIST" 2>"$PREFIX/data/biometric-renew.bootstrap.err"; then
      ok=1
      break
    fi
    sleep 0.3
  done
  if [ "$ok" = "1" ]; then
    day="天"
    [ -z "$WEEKDAY" ] || day="$(weekday_name "$WEEKDAY")"
    machine "loaded=yes" "已加载 ${LABEL}（每${day} $(printf '%02d:%02d' "$HOUR" "$MINUTE")，登录时也检查）"
  else
    note "launchctl bootstrap 失败：$(cat "$PREFIX/data/biometric-renew.bootstrap.err" 2>/dev/null)"
    machine "loaded=no" "bootstrap 失败"
    exit 2
  fi
fi


machine "action=$ACTION" "完成：$LABEL"
exit 0
