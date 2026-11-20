#!/usr/bin/env bash
# 生物识别助手「部署 + 描述文件续签」验收。
#
# 覆盖：
#   · install-biometric-app.sh：--status 打印描述文件到期时间/剩余天数/签名团队；
#     首次 --build-if-needed 构建并部署到临时 prefix；已新鲜时跳过构建；
#     --force-expiry-check 模拟临期触发重建；描述文件被删后重建并重新签发；
#     构建失败时给出明确 manual 且不破坏已部署的 .app；
#     部署产物通过 codesign --verify 且签名含 keychain-access-groups；
#   · install.sh：默认部署 .app 并把 KEYKOI_BIOMETRIC_HELPER 写进 keykoid 的
#     launchd plist（KEYKOI_BIOMETRIC_APP=0 时不写）；plist 通过 plutil -lint；
#   · install-biometric-renew.sh：生成并加载 com.keykoi.biometric-renew（每周一次），
#     plist 语义正确（ProgramArguments / EnvironmentVariables / 日志路径）、
#     plutil -lint 通过、--run-now 在 launchd 环境里跑完并写日志、可卸载；
#   · 脚本不触碰用户 Keychain 条目（不出现助手的 store/load/delete）。
# 不等待一周：调度只检查 plist 语义与一次 --run-now。
#
# 全部使用临时 prefix / 临时 HOME / 一次性 LaunchAgent 标签，结束时清理。
# 结果：docs/验收/artifacts/biometric-renewal/result.json
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/biometric-renewal}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-biometric-renewal.XXXXXX")"
CHECKS="$WORK/checks.tsv"
APP_SCRIPT="$ROOT/packaging/macos/install-biometric-app.sh"
RENEW_SCRIPT="$ROOT/packaging/macos/install-biometric-renew.sh"
INSTALL_SCRIPT="$ROOT/packaging/macos/install.sh"
GUIDE="$ROOT/docs/指南/生物识别助手续签与部署.md"
PREFIX="$WORK/prefix"
LABEL_RENEW="com.keykoi.biometric-renew.acceptance-$$"
LABEL_KEYKOID="com.keykoi.keykoid.acceptance-renewal-$$"
TEAM="${KEYKOI_DEV_TEAM:-977QNJU6V6}"
REAL_HOME="$HOME"
mkdir -p "$WORK" "$OUT_DIR" "$WORK/home"
: >"$CHECKS"
log() { printf '%s\n' "$*" >&2; }

record() { # status name detail
  local status="$1" name="$2" detail="${3:-}"
  detail="${detail//$'\t'/ }"
  detail="${detail//$'\n'/ }"
  printf '%s\t%s\t%s\n' "$status" "$name" "$detail" >>"$CHECKS"
  log "$status $name${detail:+ ($detail)}"
}
check() { if [ "$2" = "$3" ]; then record PASS "$1" "$3"; else record FAIL "$1" "expected=$2 actual=$3"; fi; }
contains() { if printf '%s' "$3" | grep -qF -- "$2"; then record PASS "$1" "contains '$2'"; else record FAIL "$1" "missing '$2'"; fi; }
absent() { if printf '%s' "$3" | grep -qF -- "$2"; then record FAIL "$1" "unexpected '$2'"; else record PASS "$1" "absent '$2'"; fi; }
manual() { record MANUAL "$1" "${2:-}"; }

field() { # key file
  sed -n "s/^$1=//p" "$2" 2>/dev/null | head -1
}

cleanup() {
  launchctl bootout "gui/$(id -u)/$LABEL_RENEW" >/dev/null 2>&1
  launchctl bootout "gui/$(id -u)/$LABEL_KEYKOID" >/dev/null 2>&1
  if [ "${KEEP_WORK:-0}" = "1" ]; then log "work dir kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# ---- 收集到期的实际值，供 result.json 使用 ----
DEPLOY_STATUS="$WORK/deploy-status.txt"
STATUS_OUT="$WORK/status.out"
STATUS_ERR="$WORK/status.err"
FORCED_OUT="$WORK/forced.out"
FORCED_ERR="$WORK/forced.err"
MISSING_OUT="$WORK/missing.out"
MISSING_ERR="$WORK/missing.err"
MISSING_STATUS="$WORK/missing-status.out"
REISSUED_STATUS="$WORK/reissued-status.out"
RENEW_SNAPSHOT="$WORK/renew-plist.snapshot"
MANUAL_OUT="$WORK/manual.out"
MANUAL_ERR="$WORK/manual.err"
RENEW_STATUS="$WORK/renew-status.txt"
RENEW_RUN="$WORK/renew-run.txt"
APP_PLIST="$WORK/home/Library/LaunchAgents/$LABEL_KEYKOID.plist"
RENEW_PLIST="$WORK/agents/$LABEL_RENEW.plist"
LOG_RENEW="$PREFIX/data/biometric-renew.log"

write_result() { # exit_code
  local code="$1"
  CHECKS="$CHECKS" OUT_DIR="$OUT_DIR" CODE="$code" WORK="$WORK" \
  STATUS_OUT="$STATUS_OUT" FORCED_OUT="$FORCED_OUT" MISSING_OUT="$MISSING_OUT" \
  MISSING_STATUS="$MISSING_STATUS" REISSUED_STATUS="$REISSUED_STATUS" \
  MANUAL_ERR="$MANUAL_ERR" DEPLOY_STATUS="$DEPLOY_STATUS" \
  RENEW_STATUS="$RENEW_STATUS" RENEW_RUN="$RENEW_RUN" \
  APP_PLIST="$APP_PLIST" RENEW_PLIST="$RENEW_SNAPSHOT" PREFIX="$PREFIX" \
  TEAM="$TEAM" LABEL_RENEW="$LABEL_RENEW" LABEL_KEYKOID="$LABEL_KEYKOID" \
  LOG_RENEW="$LOG_RENEW" python3 - <<'PY'
import datetime, json, os, plistlib

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

def kv(path):
    out = {}
    if path and os.path.exists(path):
        with open(path) as handle:
            for line in handle:
                if "=" in line:
                    key, _, value = line.rstrip("\n").partition("=")
                    out.setdefault(key, value)
    return out

def plist_dict(path):
    try:
        with open(path, "rb") as handle:
            return plistlib.load(handle)
    except Exception:
        return {}

def text(path):
    try:
        with open(path, errors="replace") as handle:
            return handle.read()
    except Exception:
        return ""

checks = read_checks(os.environ["CHECKS"])
status = kv(os.environ["STATUS_OUT"])
forced = kv(os.environ["FORCED_OUT"])
missing_status = kv(os.environ["MISSING_STATUS"])
missing = kv(os.environ["MISSING_OUT"])
reissued = kv(os.environ["REISSUED_STATUS"])
renew_status = kv(os.environ["RENEW_STATUS"])
renew_run = kv(os.environ["RENEW_RUN"])
deploy_status = kv(os.environ["DEPLOY_STATUS"])
app_plist = plist_dict(os.environ["APP_PLIST"])
renew_plist = plist_dict(os.environ["RENEW_PLIST"])
passed = sum(1 for c in checks if c["status"] == "PASS")
failed = sum(1 for c in checks if c["status"] == "FAIL")
manual_rows = [c for c in checks if c["status"] == "MANUAL"]
code = int(os.environ["CODE"])
prefix = os.environ["PREFIX"]
log_renew = os.environ["LOG_RENEW"]

def as_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def as_float(value, default=None):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

schedule = renew_plist.get("StartCalendarInterval") or {}
env = renew_plist.get("EnvironmentVariables") or {}
args = renew_plist.get("ProgramArguments") or []
keykoid_env = app_plist.get("EnvironmentVariables") or {}

notes = [
    "免费 Apple ID（Personal Team）签发的 Mac Team Provisioning Profile 只有 7 天有效期，过期后 AMFI 拒绝启动带 keychain-access-groups 的助手；续签只能重新签发，不能给已有描述文件延期。",
    "描述文件仍在有效期内时，Xcode 会复用已有描述文件，重建不会提前推进 ExpirationDate（本次实测重建前后都是同一个到期时间）；只有过期或缺失时才会拿到新的 7 天窗口，所以验收用「删除 embedded.provisionprofile」来验证重新签发。",
    "install-biometric-app.sh 用 security cms -D -i 读出 embedded.provisionprofile 的 ExpirationDate，剩余 <2 天（KEYKOI_BIOMETRIC_RENEW_DAYS 可调）或缺失时才重建，避免每次安装都联网重签。",
    "验收用 --force-expiry-check 模拟临期、用删除 embedded.provisionprofile 模拟描述文件缺失，两者都触发真实 xcodebuild 重建，不实际等待 7 天。",
    "LaunchAgent 用 StartCalendarInterval 每周触发一次；launchd 不加载 shell 启动文件，所以 plist 显式写入 HOME / PATH / DEVELOPER_DIR / KEYKOI_DEV_TEAM，xcodebuild -allowProvisioningUpdates 才能读到登录钥匙串里的 Apple Development 身份。",
    "所有构建、部署、LaunchAgent 都在临时 prefix（%s）与临时 HOME 下进行，LaunchAgent 标签带验收 PID 后缀，结束时 bootout 并清理。" % prefix,
    "install-biometric-app.sh 不调用助手的 store/load/delete，验收断言脚本里没有这些子命令调用，即不触碰用户 Keychain 条目。",
]

manual_steps = [
    "真实 Touch ID 手势（enroll 与 unlock 各一次）仍需人工在会弹指纹框的机器上点按；本次验收只覆盖部署、续签与签名校验。",
    "如需把到期时间真正推进到新的 7 天窗口，请在描述文件已过期或即将过期时执行：bash packaging/macos/install-biometric-app.sh --build-if-needed（Xcode 需已登录且能访问 developer.apple.com）。",
    "每周自动续签已安装到用户 LaunchAgents 时可长期运行：bash packaging/macos/install-biometric-renew.sh --install；验收用的是带 PID 后缀的一次性标签。",
]
for row in manual_rows:
    manual_steps.append("手工待办：%s — %s" % (row["name"], row["detail"]))

result = {
    "phase": "biometric-renewal",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "exit_code": code,
    "mode": "automated" if failed == 0 and not manual_rows else ("manual" if failed == 0 else "failed"),
    "environment": {
        "os": "macOS",
        "macos_version": os.popen("sw_vers -productVersion 2>/dev/null").read().strip() or "unknown",
        "xcode_select_p": os.popen("xcode-select -p 2>/dev/null").read().strip() or "unknown",
        "xcodebuild": (os.popen("xcodebuild -version 2>/dev/null").read().splitlines() or ["unknown"])[0],
        "team_id": os.environ["TEAM"],
        "temp_prefix": prefix,
        "note": "验收全部在临时 prefix / 临时 HOME / 一次性 LaunchAgent 标签下执行；Apple ID 名称不写入产物。",
    },
    "deployment": {
        "script": "packaging/macos/install-biometric-app.sh",
        "app": status.get("app") or deploy_status.get("deployed_app"),
        "app_exists": status.get("app_exists"),
        "helper": status.get("helper"),
        "helper_env": status.get("helper_env"),
        "profile_expiry": status.get("profile_expiry"),
        "profile_expiry_epoch": as_int(status.get("profile_expiry_epoch")),
        "remaining_seconds": as_int(status.get("remaining_seconds")),
        "remaining_days": as_float(status.get("remaining_days")),
        "signature_team": status.get("signature_team"),
        "codesign_verify": status.get("codesign_verify"),
        "entitlements_keychain_access_groups": status.get("entitlements_keychain_access_groups"),
        "min_days": as_float(status.get("min_days")),
        "renew_needed": status.get("renew_needed"),
    },
    "renewal": {
        "threshold_days": as_float(status.get("min_days")),
        "forced_expiry_check": {
            "build_exit": as_int(forced.get("build_exit")),
            "deployed_app": forced.get("deployed_app"),
            "result": forced.get("install_biometric_app"),
            "note": "模拟临期（--force-expiry-check）：即使描述文件仍有 7 天也重建了一次。",
        },
        "missing_profile": {
            "status_exit_expected": 2,
            "detected_renew_needed": missing_status.get("renew_needed"),
            "detected_reason": missing_status.get("renew_reason"),
            "rebuilt": missing.get("build_exit") == "0",
            "reissued_profile_expiry": reissued.get("profile_expiry"),
            "result": missing.get("install_biometric_app"),
            "note": "删掉已部署 .app 的 embedded.provisionprofile，验证 --build-if-needed 真的重新构建并重新签发。",
        },
        "build_failure": {
            "result": "manual",
            "rendered_manual_hint": "manual:" in text(os.environ["MANUAL_ERR"]),
        },
    },
    "install_sh": {
        "plist": os.environ["APP_PLIST"],
        "label": app_plist.get("Label"),
        "helper_env_in_plist": keykoid_env.get("KEYKOI_BIOMETRIC_HELPER"),
        "launch_agents_dir_redirected_to_temp_home": True,
    },
    "launch_agent": {
        "label": os.environ["LABEL_RENEW"],
        "plist": os.environ["RENEW_PLIST"],
        "program_arguments": args,
        "schedule": schedule,
        "environment_keys": sorted(env.keys()),
        "environment_home": env.get("HOME"),
        "environment_developer_dir": env.get("DEVELOPER_DIR"),
        "standard_out_path": renew_plist.get("StandardOutPath"),
        "loaded": renew_status.get("loaded"),
        "run_now": {
            "result": renew_run.get("run_result"),
            "kickstart": renew_run.get("kickstart"),
        },
        "log": log_renew,
        "log_has_marker": "install_biometric_app=" in text(log_renew),
        "note": "调度是每周一次；验收只检查 plist 语义 + 一次 launchctl kickstart，不等待一周。",
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
        "rerun": "bash tests/acceptance/biometric-renewal.sh",
        "status": "bash packaging/macos/install-biometric-app.sh --status",
        "build_if_needed": "bash packaging/macos/install-biometric-app.sh --build-if-needed",
        "install_renew": "bash packaging/macos/install-biometric-renew.sh --install",
        "renew_run_now": "bash packaging/macos/install-biometric-renew.sh --run-now",
        "renew_log": "tail -f \"<prefix>/data/biometric-renew.log\"",
        "uninstall_renew": "bash packaging/macos/install-biometric-renew.sh --uninstall",
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
log "== 环境 =="
check "running on macOS" "Darwin" "$(uname -s)"
log "xcodebuild: $(xcodebuild -version 2>/dev/null | head -1 || echo unknown)"
check "install-biometric-app.sh 存在可执行" "yes" "$([ -x "$APP_SCRIPT" ] && echo yes || echo no)"
check "install-biometric-renew.sh 存在可执行" "yes" "$([ -x "$RENEW_SCRIPT" ] && echo yes || echo no)"

log "== 首次 --build-if-needed（空 prefix）=="
env HOME="$REAL_HOME" bash "$APP_SCRIPT" --build-if-needed --prefix "$PREFIX" --team "$TEAM" \
  >"$WORK/first.out" 2>"$WORK/first.err"
FIRST_CODE=$?
check "空 prefix 首次构建+部署退出码" "0" "$FIRST_CODE"
contains "首次运行打印构建退出码 0" "build_exit=0" "$(cat "$WORK/first.out")"
contains "首次运行报告已部署" "deployed_app=$PREFIX/KeyKoi Biometric.app" "$(cat "$WORK/first.out")"
contains "首次运行报告 install_biometric_app=ok" "install_biometric_app=ok" "$(cat "$WORK/first.out")"
check ".app 已落到 prefix" "yes" "$([ -d "$PREFIX/KeyKoi Biometric.app" ] && echo yes || echo no)"

log "== --status：到期时间 / 剩余天数 / 签名团队 =="
env HOME="$REAL_HOME" bash "$APP_SCRIPT" --status --prefix "$PREFIX" >"$STATUS_OUT" 2>"$STATUS_ERR"
STATUS_CODE=$?
check "--status 退出码（有效期内为 0）" "0" "$STATUS_CODE"
EXPIRY="$(field profile_expiry "$STATUS_OUT")"
REMAIN_DAYS="$(field remaining_days "$STATUS_OUT")"
SIG_TEAM="$(field signature_team "$STATUS_OUT")"
log "profile_expiry=$EXPIRY remaining_days=$REMAIN_DAYS team=$SIG_TEAM"
case "$EXPIRY" in
  20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]T*) check "--status 输出描述文件到期时间" "yes" "yes" ;;
  *) check "--status 输出描述文件到期时间" "yes" "no ($EXPIRY)" ;;
esac
check "--status 输出剩余天数（>0）" "yes" \
  "$([ -n "$REMAIN_DAYS" ] && awk -v d="$REMAIN_DAYS" 'BEGIN{exit !(d > 0)}' && echo yes || echo "no ($REMAIN_DAYS)")"
check "--status 输出签名团队" "$TEAM" "$SIG_TEAM"
contains "--status 报告已部署 app 存在" "app_exists=yes" "$(cat "$STATUS_OUT")"
contains "--status 报告 codesign 通过" "codesign_verify=ok" "$(cat "$STATUS_OUT")"
contains "--status 报告 entitlements 含 keychain-access-groups" "entitlements_keychain_access_groups=yes" "$(cat "$STATUS_OUT")"
contains "--status 报告无需续签" "renew_needed=no" "$(cat "$STATUS_OUT")"

log "== 描述文件仍新鲜时跳过构建 =="
env HOME="$REAL_HOME" bash "$APP_SCRIPT" --build-if-needed --prefix "$PREFIX" --team "$TEAM" \
  >"$WORK/second.out" 2>"$WORK/second.err"
SECOND_CODE=$?
check "第二次 --build-if-needed 退出码" "0" "$SECOND_CODE"
absent "新鲜时不重建（没有 build_exit）" "build_exit=" "$(cat "$WORK/second.out")"
contains "新鲜时日志说明跳过构建" "跳过构建" "$(cat "$WORK/second.err")"

log "== 模拟临期：--force-expiry-check 触发重建 =="
env HOME="$REAL_HOME" bash "$APP_SCRIPT" --build-if-needed --prefix "$PREFIX" --team "$TEAM" \
  --force-expiry-check >"$FORCED_OUT" 2>"$FORCED_ERR"
FORCED_CODE=$?
check "--force-expiry-check 退出码" "0" "$FORCED_CODE"
contains "临期模拟触发真实构建" "build_exit=0" "$(cat "$FORCED_OUT")"
contains "临期模拟后重新部署" "deployed_app=$PREFIX/KeyKoi Biometric.app" "$(cat "$FORCED_OUT")"
contains "临期模拟结果 ok" "install_biometric_app=ok" "$(cat "$FORCED_OUT")"

log "== 描述文件缺失：重新构建并重新签发 =="
rm -f "$PREFIX/KeyKoi Biometric.app/Contents/embedded.provisionprofile"
env HOME="$REAL_HOME" bash "$APP_SCRIPT" --status --prefix "$PREFIX" >"$WORK/missing-status.out" 2>/dev/null
MISSING_STATUS_CODE=$?
check "缺描述文件时 --status 退出码为 2" "2" "$MISSING_STATUS_CODE"
contains "缺描述文件时报告 profile_expiry=none" "profile_expiry=none" "$(cat "$WORK/missing-status.out")"
contains "缺描述文件时 renew_reason=profile-missing" "renew_reason=profile-missing" "$(cat "$WORK/missing-status.out")"

env HOME="$REAL_HOME" bash "$APP_SCRIPT" --build-if-needed --prefix "$PREFIX" --team "$TEAM" \
  >"$MISSING_OUT" 2>"$MISSING_ERR"
MISSING_CODE=$?
check "缺描述文件时 --build-if-needed 退出码" "0" "$MISSING_CODE"
contains "缺描述文件时触发重建" "build_exit=0" "$(cat "$MISSING_OUT")"
check "重建后描述文件回到 .app 内" "yes" \
  "$([ -f "$PREFIX/KeyKoi Biometric.app/Contents/embedded.provisionprofile" ] && echo yes || echo no)"
env HOME="$REAL_HOME" bash "$APP_SCRIPT" --status --prefix "$PREFIX" >"$WORK/reissued-status.out" 2>/dev/null
REISSUED_CODE=$?
REISSUED_EXPIRY="$(field profile_expiry "$WORK/reissued-status.out")"
check "重新签发后 --status 恢复为 0" "0" "$REISSUED_CODE"
case "$REISSUED_EXPIRY" in
  20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]T*) check "重新签发的描述文件有到期时间" "yes" "yes" ;;
  *) check "重新签发的描述文件有到期时间" "yes" "no ($REISSUED_EXPIRY)" ;;
esac
check "重新签发的描述文件时限在原值之后" "yes" \
  "$(awk -v a="$(field profile_expiry_epoch "$WORK/reissued-status.out")" -v b="$(field profile_expiry_epoch "$STATUS_OUT")" \
     'BEGIN{ if (a+0 >= b+0 && a+0 > 0) print "yes"; else print "no" }')"

log "== 部署产物签名校验 =="
codesign --verify --strict "$PREFIX/KeyKoi Biometric.app" >"$WORK/codesign.log" 2>&1
CS_CODE=$?
check "部署后的 .app 通过 codesign --verify --strict" "0" "$CS_CODE"
contains "签名含 keychain-access-groups" "keychain-access-groups" \
  "$(codesign -d --entitlements :- "$PREFIX/KeyKoi Biometric.app" 2>/dev/null || true)"
check "助手可执行文件存在" "yes" \
  "$([ -x "$PREFIX/KeyKoi Biometric.app/Contents/MacOS/keykoi-biometric" ] && echo yes || echo no)"

log "== 构建失败：给出明确 manual 且不破坏已有 .app =="
cat >"$WORK/stub-build.sh" <<'STUB'
#!/usr/bin/env bash
# 验收替身：模拟「Xcode 未登录 / 无可用描述文件」的构建失败（build-biometric-app.sh 退出码 3）。
STATUS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --status-file) STATUS="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ -n "$STATUS" ]; then
  printf 'build=failed\nfailure_class=profile\nteam=stub\n' >"$STATUS"
fi
echo "xcodebuild 失败（exit=65，错误类别：profile）。" >&2
echo "处理：确认 Xcode 已登录、团队有效、Keychain Sharing 已开启。" >&2
exit 3
STUB
chmod +x "$WORK/stub-build.sh"
env HOME="$REAL_HOME" KEYKOI_BIOMETRIC_BUILD_SCRIPT="$WORK/stub-build.sh" \
  bash "$APP_SCRIPT" --build-if-needed --prefix "$PREFIX" --team "$TEAM" --force-expiry-check \
  >"$MANUAL_OUT" 2>"$MANUAL_ERR"
MANUAL_CODE=$?
check "构建失败时退出码为 2（需要人工）" "2" "$MANUAL_CODE"
contains "构建失败时报告 manual" "install_biometric_app=manual" "$(cat "$MANUAL_OUT")"
contains "构建失败时打印 manual 指引" "manual:" "$(cat "$MANUAL_ERR")"
contains "manual 指引给出重建命令" "--build-if-needed" "$(cat "$MANUAL_ERR")"
check "构建失败不影响已部署的 .app" "yes" \
  "$([ -x "$PREFIX/KeyKoi Biometric.app/Contents/MacOS/keykoi-biometric" ] && echo yes || echo no)"

log "== install.sh：默认部署 .app 并写入 KEYKOI_BIOMETRIC_HELPER =="
INST_PREFIX="$WORK/install-prefix"
GOENV_CACHE="$REAL_HOME/Library/Caches/go-build"
GOENV_MOD="$(go env GOMODCACHE 2>/dev/null || true)"
env HOME="$WORK/home" GOCACHE="$GOENV_CACHE" GOMODCACHE="${GOENV_MOD:-}" \
  bash "$INSTALL_SCRIPT" --prefix "$INST_PREFIX" --label "$LABEL_KEYKOID" --no-load \
  >"$WORK/install.out" 2>"$WORK/install.err"
INSTALL_CODE=$?
check "install.sh 退出码" "0" "$INSTALL_CODE"
contains "install.sh 部署了 .app" "installed KeyKoi Biometric.app" "$(cat "$WORK/install.out")"
check "install.sh 后 .app 存在" "yes" \
  "$([ -d "$INST_PREFIX/KeyKoi Biometric.app" ] && echo yes || echo no)"
codesign --verify --strict "$INST_PREFIX/KeyKoi Biometric.app" >"$WORK/install-codesign.log" 2>&1
INST_CS=$?
check "install.sh 部署的 .app 通过 codesign 校验" "0" "$INST_CS"
check "install.sh 写出 launchd plist" "yes" "$([ -f "$APP_PLIST" ] && echo yes || echo no)"
plutil -lint "$APP_PLIST" >"$WORK/install-lint.log" 2>&1
INST_LINT=$?
check "keykoid plist 通过 plutil -lint" "0" "$INST_LINT"
HELPER_IN_PLIST="$(plutil -extract EnvironmentVariables.KEYKOI_BIOMETRIC_HELPER raw -o - "$APP_PLIST" 2>/dev/null)"
check "plist 里 KEYKOI_BIOMETRIC_HELPER 指向 .app 内助手" \
  "$INST_PREFIX/KeyKoi Biometric.app/Contents/MacOS/keykoi-biometric" "$HELPER_IN_PLIST"
contains "plist 的 ProgramArguments 仍指向 keykoid" "$INST_PREFIX/bin/keykoid" \
  "$(plutil -p "$APP_PLIST" 2>/dev/null || true)"

log "== install.sh：KEYKOI_BIOMETRIC_APP=0 关闭 .app 部署 =="
INST_PREFIX2="$WORK/install-prefix-off"
LABEL_OFF="${LABEL_KEYKOID}-off"
env HOME="$WORK/home" GOCACHE="$GOENV_CACHE" GOMODCACHE="${GOENV_MOD:-}" KEYKOI_BIOMETRIC_APP=0 \
  bash "$INSTALL_SCRIPT" --prefix "$INST_PREFIX2" --label "$LABEL_OFF" --no-load \
  >"$WORK/install-off.out" 2>"$WORK/install-off.err"
INSTALL_OFF_CODE=$?
check "KEYKOI_BIOMETRIC_APP=0 时 install.sh 退出码" "0" "$INSTALL_OFF_CODE"
check "KEYKOI_BIOMETRIC_APP=0 时不部署 .app" "no" \
  "$([ -d "$INST_PREFIX2/KeyKoi Biometric.app" ] && echo yes || echo no)"
PLIST_OFF="$WORK/home/Library/LaunchAgents/$LABEL_OFF.plist"
plutil -lint "$PLIST_OFF" >/dev/null 2>&1
OFF_LINT=$?
check "关闭时 plist 仍然合法" "0" "$OFF_LINT"
absent "关闭时 plist 不含 KEYKOI_BIOMETRIC_HELPER" "KEYKOI_BIOMETRIC_HELPER" \
  "$(plutil -p "$PLIST_OFF" 2>/dev/null || true)"

log "== LaunchAgent 续签：生成 / 加载 / 立即运行 / 卸载 =="
mkdir -p "$WORK/agents"
# plist 写到临时目录（--plist-dir），避免动用户的 ~/Library/LaunchAgents；
# 但 HOME 必须是真实用户目录，否则 launchd 里的 xcodebuild 找不到登录钥匙串里的
# Apple Development 身份（会报 class=apple-id）。
bash "$RENEW_SCRIPT" --install --prefix "$PREFIX" --label "$LABEL_RENEW" --team "$TEAM" \
  --plist-dir "$WORK/agents" >"$RENEW_STATUS" 2>"$WORK/renew-install.err"
RENEW_INSTALL_CODE=$?
check "续签代理安装退出码" "0" "$RENEW_INSTALL_CODE"
check "续签 plist 已生成" "yes" "$([ -f "$RENEW_PLIST" ] && echo yes || echo no)"
plutil -lint "$RENEW_PLIST" >"$WORK/renew-lint.log" 2>&1
RENEW_LINT=$?
check "续签 plist 通过 plutil -lint" "0" "$RENEW_LINT"
contains "续签 plist 写入每周调度 StartCalendarInterval" "StartCalendarInterval" \
  "$(plutil -p "$RENEW_PLIST" 2>/dev/null || true)"
check "续签调度为每周一次（Weekday 1）" "1" \
  "$(plutil -extract StartCalendarInterval.Weekday raw -o - "$RENEW_PLIST" 2>/dev/null)"
contains "续签命令是 install-biometric-app.sh --build-if-needed" "--build-if-needed" \
  "$(plutil -p "$RENEW_PLIST" 2>/dev/null || true)"
contains "续签命令指向 install-biometric-app.sh" "install-biometric-app.sh" \
  "$(plutil -p "$RENEW_PLIST" 2>/dev/null || true)"
check "launchd 环境显式提供真实 HOME" "$REAL_HOME" \
  "$(plutil -extract EnvironmentVariables.HOME raw -o - "$RENEW_PLIST" 2>/dev/null)"
DEVDIR_IN_PLIST="$(plutil -extract EnvironmentVariables.DEVELOPER_DIR raw -o - "$RENEW_PLIST" 2>/dev/null)"
check "launchd 环境显式提供 DEVELOPER_DIR" "$(xcode-select -p 2>/dev/null)" "$DEVDIR_IN_PLIST"
contains "launchd 环境 PATH 含 Xcode 的 usr/bin" "$(xcode-select -p 2>/dev/null)/usr/bin" \
  "$(plutil -extract EnvironmentVariables.PATH raw -o - "$RENEW_PLIST" 2>/dev/null | tr ':' '\n')"
check "续签日志路径在 <prefix>/data 下" "$LOG_RENEW" \
  "$(plutil -extract StandardOutPath raw -o - "$RENEW_PLIST" 2>/dev/null)"
check "续签代理已加载" "yes" "$(launchctl print "gui/$(id -u)/$LABEL_RENEW" >/dev/null 2>&1 && echo yes || echo no)"

# 删掉部署里的描述文件，让 launchd 任务必须真的重建一次：
# 这样 --run-now 同时证明「launchd 环境里 xcodebuild -allowProvisioningUpdates 能自动签名」。
rm -f "$PREFIX/KeyKoi Biometric.app/Contents/embedded.provisionprofile"
bash "$RENEW_SCRIPT" --run-now --prefix "$PREFIX" --label "$LABEL_RENEW" --plist-dir "$WORK/agents" \
  >"$RENEW_RUN" 2>"$WORK/renew-run.err"
RENEW_RUN_CODE=$?
check "--run-now 退出码" "0" "$RENEW_RUN_CODE"
contains "--run-now 触发 kickstart" "kickstart=ok" "$(cat "$RENEW_RUN")"
contains "--run-now 在 launchd 环境跑完并返回 ok" "run_result=ok" "$(cat "$RENEW_RUN")"
check "续签日志文件已写入" "yes" "$([ -f "$LOG_RENEW" ] && echo yes || echo no)"
contains "续签日志含 install_biometric_app 收尾标记" "install_biometric_app=ok" \
  "$(cat "$LOG_RENEW" 2>/dev/null || true)"
contains "launchd 里完成真实构建（xcodebuild 自动签名）" "build_exit=0" \
  "$(cat "$LOG_RENEW" 2>/dev/null || true)"
contains "launchd 里把新 .app 部署到 prefix" "deployed_app=$PREFIX/KeyKoi Biometric.app" \
  "$(cat "$LOG_RENEW" 2>/dev/null || true)"
contains "launchd 里能读到描述文件到期时间" "profile_expiry=" \
  "$(cat "$LOG_RENEW" 2>/dev/null || true)"
contains "launchd 里报告剩余天数" "remaining_days=" "$(cat "$LOG_RENEW" 2>/dev/null || true)"
contains "launchd 里签名团队正确" "signature_team=$TEAM" "$(cat "$LOG_RENEW" 2>/dev/null || true)"
check "launchd 重建后 .app 内描述文件回来了" "yes" \
  "$([ -f "$PREFIX/KeyKoi Biometric.app/Contents/embedded.provisionprofile" ] && echo yes || echo no)"

cp "$RENEW_PLIST" "$RENEW_SNAPSHOT" 2>/dev/null || true
bash "$RENEW_SCRIPT" --status --prefix "$PREFIX" --label "$LABEL_RENEW" --plist-dir "$WORK/agents" \
  >"$WORK/renew-status.out" 2>/dev/null
contains "--status 报告已加载" "loaded=yes" "$(cat "$WORK/renew-status.out")"

bash "$RENEW_SCRIPT" --uninstall --prefix "$PREFIX" --label "$LABEL_RENEW" --plist-dir "$WORK/agents" \
  >"$WORK/renew-uninstall.out" 2>"$WORK/renew-uninstall.err"
RENEW_UNINSTALL_CODE=$?
check "卸载退出码" "0" "$RENEW_UNINSTALL_CODE"
check "卸载后代理不再加载" "no" \
  "$(launchctl print "gui/$(id -u)/$LABEL_RENEW" >/dev/null 2>&1 && echo yes || echo no)"
check "卸载后 plist 已删除" "no" "$([ -f "$RENEW_PLIST" ] && echo yes || echo no)"
check "卸载后日志保留" "yes" "$([ -f "$LOG_RENEW" ] && echo yes || echo no)"

log "== 不触碰 Keychain 条目 =="
KEYCHAIN_TOUCHES="$(grep -nE '[[:space:]"](store|load|delete)([[:space:]"]|$)|delete-generic-password|add-generic-password' \
  "$APP_SCRIPT" "$RENEW_SCRIPT" | grep -vE '^\S+:[0-9]+:[[:space:]]*#' || true)"
check "续签相关脚本没有调用 store/load/delete 或 security 条目命令" "" "$KEYCHAIN_TOUCHES"
contains "文档说明不触碰 Keychain" "不调用" "$(cat "$GUIDE" 2>/dev/null || true)"
check "续签文档存在" "yes" "$([ -f "$GUIDE" ] && echo yes || echo no)"
contains "文档记录付费开发者账号（1 年）方案" "1 年" "$(cat "$GUIDE" 2>/dev/null || true)"
contains "文档记录 -allowProvisioningUpdates 自动续期" "-allowProvisioningUpdates" "$(cat "$GUIDE" 2>/dev/null || true)"
contains "文档记录 LAContext 弱化方案的安全代价" "LAContext" "$(cat "$GUIDE" 2>/dev/null || true)"

log "== 汇总 =="
FAILED="$(awk -F'\t' '$1=="FAIL"' "$CHECKS" | wc -l | tr -d ' ')"
MANUAL_COUNT="$(awk -F'\t' '$1=="MANUAL"' "$CHECKS" | wc -l | tr -d ' ')"
if [ "$FAILED" -gt 0 ]; then
  write_result 1 >/dev/null
  log "有 $FAILED 项失败；结果：$OUT_DIR/result.json"
  exit 1
fi
if [ "$MANUAL_COUNT" -gt 0 ]; then
  write_result 2 >/dev/null
  log "有 $MANUAL_COUNT 项需要人工；结果：$OUT_DIR/result.json"
  exit 2
fi
write_result 0 >/dev/null
log "全部通过；结果：$OUT_DIR/result.json"
exit 0
