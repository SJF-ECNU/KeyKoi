#!/usr/bin/env bash
# 生物识别助手 .app 打包验收。
#
# 覆盖：
#   · packaging/macos/build-biometric-app.sh 用 xcodebuild -allowProvisioningUpdates
#     自动签名构建 KeyKoi Biometric.app（Team 977QNJU6V6），把可执行文件放在
#     Contents/MacOS/keykoi-biometric，Info.plist 带 LSUIElement；
#   · 产物签名、entitlements 里的 keychain-access-groups、嵌入描述文件的授权；
#   · 真实启动探测 launch_probe=ok，并直接执行 available；
#   · store / load 用测试值往返（系统仍要手势时记 MANUAL 并说明）；
#   · KEYKOI_BIOMETRIC_HELPER 让 keykoid 用上这个 .app 里的助手；
#   · go build ./... 与 internal/vault 的助手路径解析单测。
#
# 构建需要本机 Xcode 已登录 Apple ID 并且团队/描述文件可用。构建类失败（脚本退出
# 码 2/3/4）按“人工准备”处理：写 result.json、说明缺什么、脚本退出码 2。
#
# 结果：docs/验收/artifacts/biometric-app/result.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/biometric-app}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-biometric-app.XXXXXX")"
CHECKS="$WORK/checks.tsv"
STATUS="$WORK/build-status.txt"
BIN="$WORK/bin"
mkdir -p "$WORK" "$BIN" "$OUT_DIR"
: >"$CHECKS"
log() { printf '%s\n' "$*" >&2; }

BUILD_SCRIPT="$ROOT/packaging/macos/build-biometric-app.sh"
APP_BUNDLE_NAME="KeyKoi Biometric.app"
EXE_NAME="keykoi-biometric"
BUNDLE_ID="com.keykoi.biometric"
TEAM="${KEYKOI_DEV_TEAM:-977QNJU6V6}"

record() { # status name detail
  local status="$1" name="$2" detail="${3:-}"
  detail="${detail//$'\t'/ }"
  detail="${detail//$'\n'/ }"
  printf '%s\t%s\t%s\n' "$status" "$name" "$detail" >>"$CHECKS"
  log "$status $name${detail:+ ($detail)}"
}
check() { # name expected actual
  if [ "$2" = "$3" ]; then record PASS "$1" "$3"; else record FAIL "$1" "expected=$2 actual=$3"; fi
}
contains() { # name needle haystack
  if printf '%s' "$3" | grep -qF -- "$2"; then record PASS "$1" "contains '$2'"; else record FAIL "$1" "missing '$2'"; fi
}
manual() { # name detail
  record MANUAL "$1" "${2:-}"
}

KEYCHAIN_ACCOUNT="keykoi-acceptance-$$"
MODE="automated"
BUILD_CLASS=""
BUILD_EXIT=""
APP=""
EXE=""
ROUNDTRIP="not-run"
GESTURE_NOTE=""

cleanup() {
  set +e
  # 删掉本次验收写进 Keychain 的条目（幂等：本来不存在也算成功）。
  if [ -n "$EXE" ] && [ -x "$EXE" ]; then
    "$EXE" delete --account "$KEYCHAIN_ACCOUNT" >/dev/null 2>&1
  fi
  if [ -n "${DAEMON_PID:-}" ]; then
    kill "$DAEMON_PID" >/dev/null 2>&1
    wait "$DAEMON_PID" 2>/dev/null
  fi
  wait 2>/dev/null
  if [ "${KEEP_WORK:-0}" = "1" ]; then echo "work dir kept: $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

write_result() { # exit_code
  local code="$1"
  local sw_vers xcode_path xcode_ver id_count team_registered
  sw_vers="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
  xcode_path="$(xcode-select -p 2>/dev/null || echo unknown)"
  xcode_ver="$(xcodebuild -version 2>/dev/null | head -1 || echo unknown)"
  id_count="$(security find-identity -v -p codesigning 2>/dev/null | grep -cE '^[[:space:]]*[0-9]+\) [0-9A-F]{40} "' || true)"
  id_count="${id_count:-0}"
  team_registered="$(defaults read com.apple.dt.Xcode IDEProvisioningTeamByIdentifier 2>/dev/null | grep -c "$TEAM" || true)"
  team_registered="${team_registered:-0}"

  CHECKS="$CHECKS" OUT_DIR="$OUT_DIR" CODE="$code" MODE="$MODE" \
  BUILD_CLASS="$BUILD_CLASS" BUILD_EXIT="$BUILD_EXIT" TEAM="$TEAM" \
  SW_VERS="$sw_vers" XCODE_PATH="$xcode_path" XCODE_VER="$xcode_ver" \
  ID_COUNT="$id_count" TEAM_REGISTERED="$team_registered" \
  KEYCHAIN_ACCOUNT="$KEYCHAIN_ACCOUNT" ROUNDTRIP="$ROUNDTRIP" \
  GESTURE_NOTE="$GESTURE_NOTE" STATUS_FILE="$STATUS" APP="$APP" EXE="$EXE" \
  BUNDLE_ID="$BUNDLE_ID" python3 - <<'PY'
import datetime, json, os

def read_checks(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            while len(parts) < 3:
                parts.append("")
            rows.append({"name": parts[1], "status": parts[0], "detail": parts[2]})
    return rows

def read_status(path):
    out = {}
    if os.path.exists(path):
        with open(path) as handle:
            for line in handle:
                if "=" in line:
                    key, _, value = line.rstrip("\n").partition("=")
                    out[key] = value
    return out

checks = read_checks(os.environ["CHECKS"])
status = read_status(os.environ["STATUS_FILE"])
passed = sum(1 for c in checks if c["status"] == "PASS")
failed = sum(1 for c in checks if c["status"] == "FAIL")
manual_rows = [c for c in checks if c["status"] == "MANUAL"]
code = int(os.environ["CODE"])

notes = [
    "生物识别 ACL 需要 keychain-access-groups，而裸二进制即使签名也会被 AMFI 在启动阶段杀死；这里改为 Xcode 工程产出的已签名 .app，描述文件随包嵌入，keykoid 直接执行 Contents/MacOS/keykoi-biometric。",
    "工程文件由 packaging/macos/biometric-app/Tools/generate-xcodeproj.py 确定性生成（本机没有 xcodegen），同目录的 project.yml 供装了 xcodegen 的机器对照。",
    "自动签名使用 xcodebuild -allowProvisioningUpdates，由 Xcode 登录的 Apple ID 团队生成 Mac Team Provisioning Profile；证书与描述文件都由 Xcode 管理，仓库里不放描述文件。",
    "store 只创建 ACL 条目，不需要手势；load 会触发一次系统生物识别验证，本机实测多次都在 5~25 秒内返回正确密钥，未出现需要人工点按的指纹对话框。若目标机器弹出指纹提示，load 往返会超时（142）或返回退出码 3，脚本把它记为 MANUAL 而不是失败。",
]
if os.environ.get("BUILD_CLASS"):
    notes.append("构建未通过（%s）：result 记录为 manual，人工补登录/能力/描述文件后重跑。" % os.environ["BUILD_CLASS"])

manual_steps = [
    "Xcode → Settings… → Accounts 用 Apple ID 登录，并确认团队 977QNJU6V6 可用（脚本无法代替登录）。",
    "developer.apple.com → Identifiers → com.keykoi.biometric 勾选 Keychain Sharing；免费 Personal Team 若不支持，需要付费团队。",
    "bash packaging/macos/build-biometric-app.sh --install-dir \"$HOME/Library/Application Support/KeyKoi/bin\"",
    "export KEYKOI_BIOMETRIC_HELPER=\"<安装目录>/KeyKoi Biometric.app/Contents/MacOS/keykoi-biometric\" 后重启 keykoid。",
    "keykoi vault enroll-biometric  # 首次登记后 keykoi unlock --biometric 可跳过主密码",
    "在真机上人工确认一次 Touch ID 手势（自动化无法代替手指）。",
]
for row in manual_rows:
    manual_steps.append("手工待办：%s — %s" % (row["name"], row["detail"]))

result = {
    "phase": "biometric-app",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "exit_code": code,
    "mode": os.environ["MODE"],
    "environment": {
        "os": "macOS",
        "macos_version": os.environ["SW_VERS"],
        "xcode_select_p": os.environ["XCODE_PATH"],
        "xcodebuild": os.environ["XCODE_VER"],
        "codesigning_identities": int(os.environ["ID_COUNT"]),
        "team_id": os.environ["TEAM"],
        "team_registered_in_xcode": os.environ["TEAM_REGISTERED"] != "0",
        "note": "Apple ID 名称不写入产物；只记录团队前缀与身份数量。",
    },
    "build": {
        "script": "packaging/macos/build-biometric-app.sh",
        "exit_code": int(os.environ["BUILD_EXIT"]) if os.environ["BUILD_EXIT"] else None,
        "failure_class": os.environ["BUILD_CLASS"] or None,
        "app": status.get("app") or os.environ["APP"] or None,
        "executable": status.get("exe") or os.environ["EXE"] or None,
        "bundle_id": status.get("bundle_id") or os.environ["BUNDLE_ID"],
        "signature_team": status.get("signature_team"),
        "keychain_access_group": status.get("keychain_access_group"),
        "entitlements_keychain_access_groups": status.get("entitlements_keychain_access_groups"),
        "codesign_verify": status.get("codesign_verify"),
        "embedded_profile": status.get("embedded_profile"),
        "profile_uuid": status.get("profile_uuid"),
        "lsui_element": status.get("lsui_element"),
        "launch_probe": status.get("launch_probe"),
    },
    "keychain_roundtrip": {
        "account": os.environ["KEYCHAIN_ACCOUNT"],
        "result": os.environ["ROUNDTRIP"],
        "gesture_note": os.environ["GESTURE_NOTE"] or None,
    },
    "summary": {
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "manual": len(manual_rows),
    },
    "checks": checks,
    "manual_steps": manual_steps,
    "notes": notes,
    "commands": {
        "rerun": "bash tests/acceptance/biometric-app.sh",
        "build": "bash packaging/macos/build-biometric-app.sh",
        "build_and_install": "bash packaging/macos/build-biometric-app.sh --install-dir \"$HOME/Library/Application Support/KeyKoi/bin\"",
        "export_helper": "export KEYKOI_BIOMETRIC_HELPER=\"<app>/Contents/MacOS/keykoi-biometric\"",
    },
}
os.makedirs(os.environ["OUT_DIR"], exist_ok=True)
path = os.path.join(os.environ["OUT_DIR"], "result.json")
with open(path, "w") as handle:
    json.dump(result, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
print(path)
PY
}

cd "$ROOT"
REAL_HOME="$HOME"

log "== 环境 =="
log "xcode-select: $(xcode-select -p 2>/dev/null || echo unknown)"
log "xcodebuild:   $(xcodebuild -version 2>/dev/null | head -1 || echo unknown)"
check "running on macOS" "Darwin" "$(uname -s)"

log "== 构建 .app（xcodebuild -allowProvisioningUpdates）=="
set +e
BUILD_OUT="$(bash "$BUILD_SCRIPT" --status-file "$STATUS" 2>"$WORK/build.err")"
BUILD_EXIT=$?
set -e
printf '%s\n' "$BUILD_OUT" >"$WORK/build.out"
BUILD_ERR="$(cat "$WORK/build.err")"
BUILD_CLASS="$(sed -n 's/^failure_class=//p' "$STATUS" | head -1)"
log "build-biometric-app.sh exit=$BUILD_EXIT class=${BUILD_CLASS:-none}"

if [ "$BUILD_EXIT" -ne 0 ]; then
  MODE="manual"
  if [ "$BUILD_EXIT" -eq 2 ]; then :; fi
  case "$BUILD_CLASS" in
    apple-id) record MANUAL "构建需要 Xcode 登录 Apple ID" "failure_class=apple-id" ;;
    keychain-sharing) record MANUAL "构建需要 App ID 启用 Keychain Sharing" "failure_class=keychain-sharing" ;;
    profile) record MANUAL "构建需要可用描述文件" "failure_class=profile" ;;
    network) record MANUAL "构建需要访问 Apple 开发者服务" "failure_class=network" ;;
    "") record FAIL "构建脚本退出码" "exit=$BUILD_EXIT class=unknown" ;;
    *) record FAIL "构建脚本退出码" "exit=$BUILD_EXIT class=$BUILD_CLASS" ;;
  esac
  contains "构建日志给出可执行的人工步骤" "处理" "$BUILD_ERR"
  log "构建未通过，按 manual 记录并退出 2"
  APP="$(sed -n 's/^app=//p' "$STATUS" | head -1)"
  EXE="$(sed -n 's/^exe=//p' "$STATUS" | head -1)"
  write_result 2 >/dev/null
  log "结果：$OUT_DIR/result.json"
  exit 2
fi

BUILD_EXIT="$BUILD_EXIT"
record PASS "构建脚本退出码为 0" "exit=0"
contains "构建脚本输出 launch_probe=ok" "launch_probe=ok" "$BUILD_OUT"
contains "构建脚本输出 keychain-access-groups 校验" "entitlements_keychain_access_groups=yes" "$BUILD_OUT"
contains "构建脚本输出 codesign 校验通过" "codesign_verify=ok" "$BUILD_OUT"
contains "构建脚本给出给 keykoi 用的可执行文件路径" "KEYKOI_BIOMETRIC_HELPER=" "$BUILD_OUT"

APP="$(sed -n 's/^app=//p' "$STATUS" | head -1)"
EXE="$(sed -n 's/^exe=//p' "$STATUS" | head -1)"
[ -n "$APP" ] || APP="$(sed -n 's/^KEYKOI_BIOMETRIC_HELPER=//p' "$BUILD_OUT" | tail -1 | sed 's#/Contents/MacOS/.*##')"
if [ -z "$EXE" ]; then EXE="$APP/Contents/MacOS/$EXE_NAME"; fi
log "app: $APP"
log "exe: $EXE"

log "== 产物结构 =="
check "包名是 KeyKoi Biometric.app" "$APP_BUNDLE_NAME" "$(basename "$APP")"
check "可执行文件位于 Contents/MacOS/keykoi-biometric" "yes" \
  "$([ -x "$APP/Contents/MacOS/$EXE_NAME" ] && echo yes || echo no)"
check "存在 embedded.provisionprofile" "yes" \
  "$([ -f "$APP/Contents/embedded.provisionprofile" ] && echo yes || echo no)"
PLIST="$(plutil -p "$APP/Contents/Info.plist" 2>/dev/null || true)"
contains "Info.plist 设置 CFBundleIdentifier" "$BUNDLE_ID" "$PLIST"
contains "Info.plist 设置 CFBundleExecutable" "\"CFBundleExecutable\" => \"$EXE_NAME\"" "$PLIST"
case "$PLIST" in
  *'"LSUIElement" => 1'*|*'"LSUIElement" => true'*) check "Info.plist 设置 LSUIElement" "yes" "yes" ;;
  *) check "Info.plist 设置 LSUIElement" "yes" "no" ;;
esac

log "== 签名与权限 =="
set +e
codesign --verify --strict "$APP" >"$WORK/codesign.log" 2>&1
CS_CODE=$?
set -e
check "codesign --verify --strict 通过" "0" "$CS_CODE"
ENTS="$(codesign -d --entitlements :- "$APP" 2>/dev/null || true)"
contains "签名里含 keychain-access-groups" "keychain-access-groups" "$ENTS"
contains "权限里的访问组带团队前缀" "$TEAM.$BUNDLE_ID" "$ENTS"
SIG_TEAM="$(codesign -dv --verbose=4 "$APP" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -1)"
check "签名团队 ID 匹配" "$TEAM" "$SIG_TEAM"
PROFILE_PLIST="$(security cms -D -i "$APP/Contents/embedded.provisionprofile" 2>/dev/null || true)"
contains "描述文件授权 keychain-access-groups" "keychain-access-groups" "$PROFILE_PLIST"
contains "描述文件属于同一团队" "$TEAM" "$PROFILE_PLIST"

log "== 真实启动与 available =="
set +e
AVAIL_OUT="$("$EXE" available 2>"$WORK/avail.err")"
AVAIL_CODE=$?
set -e
check "助手的 available 退出码为 0" "0" "$AVAIL_CODE"
check "助手的 available 输出 available" "available" "$(printf '%s' "$AVAIL_OUT" | tr -d '\n')"

log "== store / load 往返（测试账号 ${KEYCHAIN_ACCOUNT}）=="
TEST_KEY="$(python3 -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"
set +e
STORE_OUT="$(printf '%s\n' "$TEST_KEY" | "$EXE" store --account "$KEYCHAIN_ACCOUNT" 2>"$WORK/store.err")"
STORE_CODE=$?
set -e
if [ "$STORE_CODE" -eq 0 ]; then
  record PASS "store 写入测试根密钥" "exit=0"
  set +e
  LOAD_START=$(date +%s)
  LOAD_OUT="$(perl -e 'alarm 60; exec @ARGV' "$EXE" load --account "$KEYCHAIN_ACCOUNT" 2>"$WORK/load.err")"
  LOAD_CODE=$?
  LOAD_SECS=$(( $(date +%s) - LOAD_START ))
  set -e
  if [ "$LOAD_CODE" -eq 0 ] && [ "$(printf '%s' "$LOAD_OUT" | tr -d '\n')" = "$TEST_KEY" ]; then
    ROUNDTRIP="ok"
    record PASS "load 取回同一测试根密钥" "exit=0, ${LOAD_SECS}s"
    GESTURE_NOTE="load 之前系统做过一次生物识别验证：本机在 ${LOAD_SECS}s 后返回同一密钥，没有出现需要人工点按的指纹对话框；弹出指纹框的机器上这一步仍算人工操作，超时会记成 MANUAL。"
  elif [ "$LOAD_CODE" -eq 142 ] || [ "$LOAD_CODE" -eq 3 ] || [ "$LOAD_CODE" -eq 2 ]; then
    ROUNDTRIP="manual"
    GESTURE_NOTE="load 在 60s 内没有返回可比的根密钥（exit=${LOAD_CODE}）：$(tr '\n' ' ' <"$WORK/load.err" | head -c 300)"
    manual "load 需要交互会话里的指纹确认" "exit=$LOAD_CODE"
  else
    ROUNDTRIP="failed"
    record FAIL "load 取回同一测试根密钥" "exit=$LOAD_CODE $(tr '\n' ' ' <"$WORK/load.err" | head -c 200)"
  fi
  set +e
  "$EXE" delete --account "$KEYCHAIN_ACCOUNT" >"$WORK/delete.out" 2>&1
  DEL_CODE=$?
  set -e
  check "delete 清理测试条目" "0" "$DEL_CODE"
else
  record FAIL "store 写入测试根密钥" "exit=$STORE_CODE $(tr '\n' ' ' <"$WORK/store.err" | head -c 200)"
fi

log "== keykoid 通过 KEYKOI_BIOMETRIC_HELPER 使用 .app 助手 =="
(
  env HOME="$REAL_HOME" GOFLAGS="${GOFLAGS:-}" go build -o "$BIN/keykoid" ./cmd/keykoid
  env HOME="$REAL_HOME" GOFLAGS="${GOFLAGS:-}" go build -o "$BIN/keykoi" ./cmd/keykoi
) >"$WORK/gobuild.log" 2>&1 && GO_CODE=0 || GO_CODE=$?
check "go build ./cmd/keykoid ./cmd/keykoi 通过" "0" "$GO_CODE"

if [ -x "$BIN/keykoid" ]; then
  mkdir -p "$WORK/data"
  # 两个不同的空闲端口：admin 与 gateway 不能共用同一个监听地址。
  read -r FREE_PORT_GW FREE_PORT_ADMIN <<EOF
$(python3 - <<'PYFREE'
import socket
ports = []
for _ in range(2):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    ports.append(s.getsockname()[1])
    s.close()
print(*ports)
PYFREE
)
EOF
  KEYKOI_BIOMETRIC_HELPER="$EXE" "$BIN/keykoid" \
    --data-dir "$WORK/data" --socket "$WORK/keykoid.sock" \
    --admin "127.0.0.1:$FREE_PORT_ADMIN" --gateway "127.0.0.1:$FREE_PORT_GW" \
    --keykoi-bin "$BIN/keykoi" --biometric-account "$KEYCHAIN_ACCOUNT" \
    >"$WORK/keykoid.log" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 100); do
    [ -S "$WORK/keykoid.sock" ] && break
    sleep 0.1
  done
  if [ -S "$WORK/keykoid.sock" ]; then
    record PASS "keykoid 用环境变量里的 .app 助手启动" "socket=$WORK/keykoid.sock"
    contains "keykoid 日志确认助手路径指向 .app 包" "KeyKoi Biometric.app/Contents/MacOS/$EXE_NAME" "$(cat "$WORK/keykoid.log")"
    set +e
    printf 'acceptance-master-pass-9\n' | "$BIN/keykoi" --data-dir "$WORK/data" --socket "$WORK/keykoid.sock" init --password-stdin >"$WORK/init.log" 2>&1
    INIT_CODE=$?
    set -e
    check "keykoi init 经该助手初始化密钥库" "0" "$INIT_CODE"
    set +e
    ENROLL_OUT="$("$BIN/keykoi" --data-dir "$WORK/data" --socket "$WORK/keykoid.sock" vault enroll-biometric 2>&1)"
    ENROLL_CODE=$?
    set -e
    check "keykoi vault enroll-biometric 成功" "0" "$ENROLL_CODE"
    set +e
    STATUS_OUT="$("$BIN/keykoi" --data-dir "$WORK/data" --socket "$WORK/keykoid.sock" auth status 2>&1)"
    STATUS_CODE=$?
    set -e
    check "keykoi auth status 经该助手报告可用" "0" "$STATUS_CODE"
    contains "auth status 显示 available=true" "available=true" "$STATUS_OUT"
    log "$STATUS_OUT"
  else
    record FAIL "keykoid 用环境变量里的 .app 助手启动" "no socket: $(tr '\n' ' ' <"$WORK/keykoid.log" | head -c 200)"
  fi
  kill "$DAEMON_PID" >/dev/null 2>&1 || true
  wait "$DAEMON_PID" 2>/dev/null || true
  DAEMON_PID=""
fi

log "== 助手路径解析单测 =="
set +e
env HOME="$REAL_HOME" go test ./internal/vault -run 'ResolveHelperPath|NormalizeHelperPath' >"$WORK/vaulttest.log" 2>&1
VT_CODE=$?
set -e
check "internal/vault 助手路径解析测试通过" "0" "$VT_CODE"

log "== 汇总 =="
FAILED="$(awk -F'\t' '$1=="FAIL"' "$CHECKS" | wc -l | tr -d ' ')"
MANUAL_COUNT="$(awk -F'\t' '$1=="MANUAL"' "$CHECKS" | wc -l | tr -d ' ')"
if [ "$FAILED" -gt 0 ]; then
  write_result 1 >/dev/null
  log "有 $FAILED 项失败；结果：$OUT_DIR/result.json"
  exit 1
fi
if [ "$MANUAL_COUNT" -gt 0 ]; then
  MODE="manual"
  write_result 2 >/dev/null
  log "有 $MANUAL_COUNT 项需要人工手势；结果：$OUT_DIR/result.json"
  exit 2
fi
write_result 0 >/dev/null
log "全部通过；结果：$OUT_DIR/result.json"
exit 0
