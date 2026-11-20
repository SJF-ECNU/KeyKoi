#!/usr/bin/env bash
# 生物识别助手签名验收。
#
# 覆盖：记录本机签名环境（是否存在有效签名身份、xcode-select -p）、在临时目录里
# 对助手副本跑 packaging/macos/sign-biometric.sh，按真实环境分支断言：
#   · 有身份 → 退出码 0、签名里含 keychain-access-groups、codesign --verify 通过、
#     启动探测结果被如实记录；
#   · 无身份 → 退出码 2 且打印 Xcode / Keychain Sharing 指引。
# 另外用 PATH 替身模拟“无签名身份”分支，保证两条契约都被执行到。
#
# 真实的 Touch ID 登记（需要人工点指纹）仍然是 manual：脚本只做不弹窗的判断。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/biometric-signing}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-biometric-sign.XXXXXX")"
HELPER_DIR="$WORK/helper"; SHIM="$WORK/shim"
mkdir -p "$HELPER_DIR" "$SHIM" "$OUT_DIR"
log() { printf '%s\n' "$*" >&2; }

cleanup() {
  set +e
  wait 2>/dev/null
  if [ "${KEEP_WORK:-0}" = "1" ]; then echo "work dir kept: $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

cd "$ROOT"
# Go 工具链必须继续用真实模块缓存，否则会在临时 HOME 里重新下载全部依赖。
REAL_HOME="$HOME"
GOENV=(env HOME="$REAL_HOME")

CHECKS=()
check() { # name expected actual
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    CHECKS+=("PASS|$name|$actual"); log "PASS $name"
  else
    CHECKS+=("FAIL|$name|expected=$expected actual=$actual"); log "FAIL $name expected=$expected actual=$actual"
  fi
}
contains() { # name needle haystack
  local name="$1" needle="$2" hay="$3"
  if printf '%s' "$hay" | grep -qF -- "$needle"; then
    CHECKS+=("PASS|$name|contains '$needle'"); log "PASS $name"
  else
    CHECKS+=("FAIL|$name|missing '$needle'"); log "FAIL $name missing '$needle'"
  fi
}

# 注意：这里刻意不覆盖 HOME。签名身份来自登录钥匙串，临时 HOME 会让
# `security find-identity` 看不到身份，验收就会误报“本机没有签名身份”。

log "== 记录环境 =="
XCODE_PATH="$(xcode-select -p 2>&1 || true)"
SW_VERS="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
SW_BUILD="$(sw_vers -buildVersion 2>/dev/null || echo unknown)"
IDS="$(security find-identity -v -p codesigning 2>&1 || true)"
IDENT_COUNT="$(printf '%s\n' "$IDS" | grep -cE '^[[:space:]]*[0-9]+\) [0-9A-F]{40} "' || true)"
IDENT_COUNT="${IDENT_COUNT:-0}"
IDENTITY=""
for pattern in "Developer ID Application" "Apple Development" "Apple Distribution" "Mac Developer"; do
  IDENTITY="$(printf '%s\n' "$IDS" | sed -n "s/.*\"\(${pattern}: [^\"]*\)\".*/\1/p" | head -1)"
  [ -n "$IDENTITY" ] && { IDENTITY_KIND="$pattern"; break; }
done
IDENTITY_KIND="${IDENTITY_KIND:-none}"
TEAM=""
if [ -n "$IDENTITY" ]; then
  TEAM="$(security find-certificate -c "$IDENTITY" -p 2>/dev/null \
    | openssl x509 -noout -subject -nameopt multiline 2>/dev/null \
    | sed -n 's/.*organizationalUnitName *= *//p' | tr -d ' ' | head -1)"
fi
log "xcode-select: $XCODE_PATH"
log "valid signing identities: $IDENT_COUNT (${IDENTITY_KIND})"
if [ -n "$IDENTITY" ]; then
  check "environment reports at least one codesigning identity" "yes" "yes"
else
  check "environment reports no codesigning identity" "0" "$IDENT_COUNT"
fi

log "== 准备助手副本 =="
SRC_HELPER="$ROOT/packaging/macos/keykoi-biometric"
if [ ! -f "$SRC_HELPER" ]; then
  if bash "$ROOT/packaging/macos/build-biometric.sh" "$HELPER_DIR/keykoi-biometric" >"$WORK/build.log" 2>&1; then :; fi
else
  cp "$SRC_HELPER" "$HELPER_DIR/keykoi-biometric"
fi
HELPER="$HELPER_DIR/keykoi-biometric"
HELPER_READY=0
[ -f "$HELPER" ] && HELPER_READY=1
check "helper binary available for signing" "1" "$HELPER_READY"
if [ "$HELPER_READY" != "1" ]; then
  log "helper binary missing; cannot continue"
  exit 1
fi
chmod 755 "$HELPER"

log "== 跑签名脚本 =="
set +e
SIGN_OUT="$(bash "$ROOT/packaging/macos/sign-biometric.sh" --helper "$HELPER" 2>"$WORK/sign.err")"; SIGN_CODE=$?
set -e
SIGN_ERR="$(cat "$WORK/sign.err")"
printf '%s\n' "$SIGN_OUT" >"$WORK/sign.out"
log "sign-biometric.sh exit=$SIGN_CODE"

LAUNCH_LINE=""
SIGNED_ARTIFACT=""
if [ -f "$HELPER.signed" ]; then SIGNED_ARTIFACT="$HELPER.signed"; else SIGNED_ARTIFACT="$HELPER"; fi
SIGNED_SHA="$(shasum -a 256 "$SIGNED_ARTIFACT" | awk '{print $1}')"
SIGNED_BYTES="$(stat -f%z "$SIGNED_ARTIFACT")"
SIGNED_BASENAME="$(basename "$SIGNED_ARTIFACT")"

if [ "$IDENT_COUNT" -gt 0 ]; then
  log "== 有签名身份：签名与 entitlements 校验 =="
  check "sign script exits 0 with a real identity" "0" "$SIGN_CODE"
  contains "script reports the signing identity" "identity:" "$SIGN_OUT"
  contains "script resolves a team id" "team:" "$SIGN_OUT"
  contains "keychain-access-groups is present in the signature" "entitlements_keychain_access_groups=yes" "$SIGN_OUT"
  contains "codesign --verify passes" "codesign_verify=ok" "$SIGN_OUT"
  ENT_DUMP="$(codesign -d --entitlements :- "$SIGNED_ARTIFACT" 2>/dev/null || true)"
  contains "independent codesign dump has keychain-access-groups" "keychain-access-groups" "$ENT_DUMP"
  if [ -n "$TEAM" ]; then
    contains "entitlement group uses the certificate team id" "<string>$TEAM." "$ENT_DUMP"
    contains "signature carries the certificate team id" "signature_team=$TEAM" "$SIGN_OUT"
  fi
  set +e
  codesign --verify --strict "$SIGNED_ARTIFACT" >/dev/null 2>&1; STRICT_CODE=$?
  set -e
  check "independent strict verify of the signed artifact" "0" "$STRICT_CODE"
  LAUNCH_LINE="$(printf '%s\n' "$SIGN_OUT" | sed -n 's/^launch_probe=//p' | head -1)"
  case "$LAUNCH_LINE" in
    ok*) check "launch probe result recorded" "ok" "ok" ;;
    blocked-by-amfi*)
      check "launch probe reports the AMFI block honestly" "blocked-by-amfi" "blocked-by-amfi"
      contains "script explains the provisioning profile requirement" "描述文件" "$SIGN_ERR"
      contains "script documents the revert of the unusable signature" "deploy=reverted" "$SIGN_OUT"
      set +e
      "$HELPER" available >/dev/null 2>&1; RESTORED_CODE=$?
      set -e
      check "restored helper still answers available" "0" "$RESTORED_CODE"
      ;;
    *) check "launch probe result recorded" "recorded" "$LAUNCH_LINE" ;;
  esac
else
  log "== 无签名身份：指引与退出码 =="
  check "sign script exits 2 without an identity" "2" "$SIGN_CODE"
  contains "script names the missing identity kind" "没有找到可用的 Apple Development" "$SIGN_ERR"
  contains "script points at Xcode" "Xcode" "$SIGN_ERR"
  contains "script mentions Keychain Sharing" "Keychain Sharing" "$SIGN_ERR"
  check "no signed artifact is produced" "no" "$([ -f "$HELPER.signed" ] && echo yes || echo no)"
fi

log "== 模拟无签名身份（PATH 替身）=="
cat >"$SHIM/security" <<'SHIMEOF'
#!/usr/bin/env bash
# 模拟没有任何有效代码签名身份
case "$1" in
  find-identity) exit 0 ;;
  find-certificate) exit 0 ;;
  *) exit 1 ;;
esac
SHIMEOF
chmod 755 "$SHIM/security"
cp -f "$ROOT/packaging/macos/keykoi-biometric" "$WORK/helper2" 2>/dev/null || cp -f "$HELPER" "$WORK/helper2"
set +e
PATH="$SHIM:$PATH" bash "$ROOT/packaging/macos/sign-biometric.sh" --helper "$WORK/helper2" \
  >"$WORK/sim.out" 2>"$WORK/sim.err"; SIM_CODE=$?
set -e
SIM_ERR="$(cat "$WORK/sim.err")"
check "simulated no-identity run exits 2" "2" "$SIM_CODE"
contains "simulated run prints the Xcode guidance" "Xcode → Settings" "$SIM_ERR"
contains "simulated run prints the Keychain Sharing guidance" "Keychain Sharing" "$SIM_ERR"

log "== install.sh 可选钩子 =="
contains "install.sh exposes KEYKOI_SIGN_BIOMETRIC" "KEYKOI_SIGN_BIOMETRIC" "$(cat "$ROOT/packaging/macos/install.sh")"
contains "install.sh calls sign-biometric.sh" "sign-biometric.sh" "$(cat "$ROOT/packaging/macos/install.sh")"

log "== Go 构建 =="
set +e
BUILD_OUT="$("${GOENV[@]}" go build ./... 2>&1)"; BUILD_CODE=$?
set -e
check "go build ./... passes" "0" "$BUILD_CODE"

log "== 写验收结果 =="
printf '%s\n' "${CHECKS[@]}" >"$WORK/checks.txt"
python3 - "$WORK/checks.txt" "$OUT_DIR/result.json" "$SIGN_CODE" "$SIGN_OUT" "$SIGN_ERR" \
  "$IDENT_COUNT" "$IDENTITY_KIND" "$TEAM" "$XCODE_PATH" "$SW_VERS" "$SW_BUILD" "$LAUNCH_LINE" "$BUILD_OUT" \
  "$SIGNED_BASENAME" "$SIGNED_SHA" "$SIGNED_BYTES" <<'PY'
import json, os, re, sys, datetime, platform, subprocess

(checks_path, out_path, sign_code, sign_out, sign_err, ident_count, ident_kind,
 team, xcode_path, sw_vers, sw_build, launch_line, build_out,
 signed_basename, signed_sha, signed_bytes) = sys.argv[1:17]

checks = []
for line in open(checks_path, encoding="utf-8"):
    line = line.rstrip("\n")
    if not line:
        continue
    status, name, detail = line.split("|", 2)
    checks.append({"name": name, "status": status, "detail": detail})
passed = sum(1 for c in checks if c["status"] == "PASS")
failed = len(checks) - passed

# 签名身份里的 Apple ID 属于个人信息，产物只保留类别与团队前缀。
def redact(text):
    return re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", "<apple-id>", text or "")

fields = {}
for line in (sign_out or "").splitlines():
    # 脚本既输出 `key: value` 也输出 `key=value`；后者常带中文补充说明，取前段。
    m = re.match(r"^([a-z_]+)\s*[:=]\s*(.*)$", line)
    if m and m.group(1) not in fields:
        value = re.split(r"[（(]", m.group(2))[0].strip()
        fields[m.group(1)] = redact(value)
launch = (launch_line or "").split(" ")[0] or "not-recorded"

result = {
    "phase": "biometric-signing",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "environment": {
        "os": platform.platform(),
        "machine": platform.machine(),
        "macos_version": sw_vers,
        "macos_build": sw_build,
        "xcode_select_p": xcode_path,
        "codesigning_identities": int(ident_count) if str(ident_count).isdigit() else ident_count,
        "identity_kind": ident_kind,
        "team_id": team or "",
        "note": "签名身份的名称含 Apple ID，产物只记录类别与团队前缀；完整输出留在本次运行的临时目录。",
    },
    "signing": {
        "script": "packaging/macos/sign-biometric.sh",
        "exit_code": int(sign_code) if str(sign_code).isdigit() else sign_code,
        "identity": fields.get("identity", ""),
        "team": fields.get("team", ""),
        "provision_profile": fields.get("provision", "absent"),
        "entitlements_keychain_access_groups": fields.get("entitlements_keychain_access_groups", "no"),
        "codesign_verify": fields.get("codesign_verify", "unknown"),
        "signature_team": fields.get("signature_team", ""),
        "launch_probe": fields.get("launch_probe", launch),
        "deploy": fields.get("deploy", "unknown"),
        "signed_artifact": {
            "name": signed_basename,
            "sha256": signed_sha,
            "bytes": int(signed_bytes) if str(signed_bytes).isdigit() else signed_bytes,
            "note": "产物在本次运行的临时目录里，退出即删除；这里保留摘要作为可复核证据。",
        },
        "stderr_summary": redact(sign_err).strip().splitlines()[:6],
    },
    "summary": {"total": len(checks), "passed": passed, "failed": failed},
    "checks": checks,
    "manual_steps": [
        "在 Xcode → Settings… → Accounts 用 Apple ID 登录，生成 Apple Development 证书（脚本无法代替登录）。",
        "给 App ID 打开 Keychain Sharing 能力，导出描述文件；裸二进制不接受描述文件，需要 .app 包。",
        "把带描述文件的签名助手装进 <prefix>/bin，并确认 `keykoi-biometric available` 能启动。",
        "keykoi vault enroll-biometric  # 真机弹 Touch ID，需人工点指纹（manual）",
        "keykoi unlock --biometric      # 再次人工确认指纹",
        "keykoi auth status             # 期望 available=true enrolled=true",
    ],
    "notes": [
        "本机有有效 Apple Development 身份时，脚本能完成签名并让签名里带上 keychain-access-groups；"
        "但缺少描述文件授权时系统会在启动阶段杀死该二进制（launch_probe=blocked-by-amfi），"
        "此时脚本回滚到签名前的产物，避免装上一个起不来的助手。",
        "没有签名身份时脚本退出码 2 并打印 Xcode 登录、创建团队与 Keychain Sharing 的指引。",
        "真实 Touch ID 登记必须在交互会话里人工确认，自动化只做不弹窗的判断。",
    ],
    "go": {
        "build": "pass" if build_out == "" or "error" not in build_out.lower() else "fail",
        "build_output": (build_out or "").strip(),
    },
    "commands": {
        "rerun": "bash tests/acceptance/biometric-signing.sh",
        "sign": "bash packaging/macos/sign-biometric.sh --helper <path>/keykoi-biometric",
        "install_with_signing": "KEYKOI_SIGN_BIOMETRIC=1 bash packaging/macos/install.sh",
    },
}
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(result, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
print(f"wrote {out_path}: {passed}/{len(checks)} checks passed")
PY

FAILED_COUNT=0
for line in "${CHECKS[@]}"; do
  case "$line" in FAIL\|*) FAILED_COUNT=$((FAILED_COUNT + 1));; esac
done
if [ "$FAILED_COUNT" -ne 0 ]; then
  log "FAILED checks: $FAILED_COUNT"
  exit 1
fi
log "all biometric signing acceptance checks passed"
