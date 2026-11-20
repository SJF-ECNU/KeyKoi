#!/usr/bin/env bash
# P1 工具接入验收：脱敏预览、受管字段写入、真实验证、漂移、撤销与无关字段保护。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/p1-integration}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-int.XXXXXX")"
BIN="$WORK/bin"; mkdir -p "$BIN" "$OUT_DIR"
log() { printf '%s\n' "$*" >&2; }

cleanup() {
  set +e
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  [ -n "${UP_PID:-}" ] && kill "$UP_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

cd "$ROOT"
log "building"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/mockupstream" ./tests/fixtures/mockupstream

DATA="$WORK/data"; HOME_DIR="$WORK/home"; ADAPTERS="$WORK/adapters"
mkdir -p "$DATA" "$HOME_DIR/.aws" "$ADAPTERS"
export KEYKOI_DATA_DIR="$DATA" KEYKOI_SOCKET="$DATA/keykoid.sock" HOME="$HOME_DIR"

AWS_ID="AKIA$(openssl rand -hex 8 | tr 'a-f' 'A-F')"
AWS_SECRET="$(openssl rand -hex 20)"
AWS_SESSION="$(openssl rand -hex 24)"

"$BIN/mockupstream" --addr 127.0.0.1:0 --expect "sigv4:$AWS_ID" --addr-file "$WORK/up.addr" >"$WORK/up.log" 2>&1 &
UP_PID=$!
for i in $(seq 1 50); do [ -s "$WORK/up.addr" ] && break; sleep 0.1; done
UP="http://$(cat "$WORK/up.addr")"

"$BIN/keykoid" --data-dir "$DATA" --adapters "$ADAPTERS" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for i in $(seq 1 80); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
printf 'p1-integration-master\n' | "$BIN/keykoi" init --password-stdin >/dev/null

PRINCIPAL="principal_local_$(id -u)"
CRED="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "p1 integration key" \
  --field "access_id=$AWS_ID" --field "access_secret=$AWS_SECRET" --field "session_token=$AWS_SESSION")"
"$BIN/keykoi" --json binding add --id bind_int_aws --credential "$CRED" --origin "$UP" --route int-aws --scheme bearer >/dev/null
"$BIN/keykoi" --json grant add --principal "$PRINCIPAL" --binding bind_int_aws --mode runtime_delivery --max-lease-seconds 600 --auth permanent >/dev/null

cat > "$ADAPTERS/aws-cli-helper.yaml" <<EOF
schema_version: 1
id: aws-cli-helper
adapter_version: 1
status: verified
tool:
  executable_ref: installations.aws_cli
  executable: $(command -v aws)
  supported_os: [macos]
  verified_versions: ["$(aws --version 2>&1 | awk '{print $1}' | cut -d/ -f2)"]
credential:
  binding_ref: bind_int_aws
  delivery_mode: runtime_delivery
integration:
  mechanism: helper_config
  config_path: "~/.aws/config"
  section: "profile keykoi"
  managed_key: credential_process
  helper_args: ["helper", "aws", "--binding", "bind_int_aws"]
  verify_args: ["--profile", "keykoi", "sts", "get-caller-identity", "--endpoint-url", "{{upstream}}"]
lifecycle:
  plaintext_disk_fallback: false
  persist_session_token: false
EOF

# 已存在的用户配置包含无关字段。
cat > "$HOME_DIR/.aws/config" <<'EOF'
[profile keykoi]
region = us-east-1
output = json

[profile unrelated]
region = eu-west-1
output = text
EOF
chmod 600 "$HOME_DIR/.aws/config"

CHECKS=()
check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then CHECKS+=("PASS|$name|$actual"); log "PASS $name"
  else CHECKS+=("FAIL|$name|expected=$expected actual=$actual"); log "FAIL $name expected=$expected actual=$actual"; fi
}

log "detect + plan"
DETECT="$("$BIN/keykoi" --json integration detect --profile aws-cli-helper)"
TOOL_VERSION="$(printf '%s' "$DETECT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tool_version"])')"
check "tool detected with real version" "1" "$(python3 -c "print(1 if 'aws-cli' in '$TOOL_VERSION' else 0)")"

PLAN="$("$BIN/keykoi" --json integration plan --profile aws-cli-helper)"
PREVIEW="$(printf '%s' "$PLAN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["preview"])')"
check "preview shows only managed field" "1" "$(printf '%s' "$PREVIEW" | grep -c 'credential_process' | tr -d ' ')"
check "preview contains no secret value" "0" "$(printf '%s' "$PREVIEW" | grep -c "$AWS_SECRET" || true)"

log "attach (apply)"
"$BIN/keykoi" --json integration attach --profile aws-cli-helper >/dev/null
CFG="$HOME_DIR/.aws/config"
check "managed helper entry written" "1" "$(grep -c 'credential_process = .*helper aws --binding bind_int_aws' "$CFG" | tr -d ' ')"
check "unrelated profile preserved" "1" "$(grep -c 'region = eu-west-1' "$CFG" | tr -d ' ')"
check "existing keys preserved" "1" "$(grep -c 'output = json' "$CFG" | tr -d ' ')"
check "config has no secret" "0" "$(grep -c "$AWS_SECRET" "$CFG" || true)"
check "config mode 0600" "600" "$(stat -f '%Lp' "$CFG")"

BEFORE_HASH="$(shasum -a 256 "$CFG" | awk '{print $1}')"
"$BIN/keykoi" --json integration attach --profile aws-cli-helper >/dev/null
AFTER_HASH="$(shasum -a 256 "$CFG" | awk '{print $1}')"
check "repeated attach is idempotent" "$BEFORE_HASH" "$AFTER_HASH"

log "verify with real aws cli"
"$BIN/keykoi" --json integration verify --profile aws-cli-helper >/dev/null
STATUS="$("$BIN/keykoi" --json integration status --id aws-cli-helper)"
check "integration verified" "verified" "$(printf '%s' "$STATUS" | python3 -c 'import json,sys; print(json.load(sys.stdin)["integration"]["State"])')"
check "no drift initially" "False" "$(printf '%s' "$STATUS" | python3 -c 'import json,sys; print(json.load(sys.stdin)["drift"])')"

log "drift: user edits the managed field"
ATTACHED_VALUE="$(grep '^credential_process = ' "$CFG")"
python3 - "$CFG" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read().replace("credential_process = ", "credential_process = user-command #", 1)
open(p, "w").write(s)
PY
set +e
"$BIN/keykoi" --json integration verify --profile aws-cli-helper >"$WORK/drift.out" 2>"$WORK/drift.err"
DRIFT_EXIT=$?
set -e
check "verify fails on drift" "1" "$DRIFT_EXIT"
STATUS2="$("$BIN/keykoi" --json integration status --id aws-cli-helper)"
check "drift reported" "True" "$(printf '%s' "$STATUS2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["drift"])')"
check "state unverified after drift" "unverified" "$(printf '%s' "$STATUS2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["integration"]["State"])')"

log "version outside verified range stays unverified"
python3 - "$ADAPTERS/aws-cli-helper.yaml" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s = re.sub(r'verified_versions: \[.*?\]', 'verified_versions: ["0.0.0-not-this-build"]', s, count=1)
open(p, "w").write(s)
PY
# 重新加载声明：daemon 每次按需读取，无需重启。
set +e
"$BIN/keykoi" --json integration verify --profile aws-cli-helper >"$WORK/version.out" 2>"$WORK/version.err"
VERSION_EXIT=$?
set -e
check "verify refuses unverified tool version" "1" "$VERSION_EXIT"
STATUS3="$("$BIN/keykoi" --json integration status --id aws-cli-helper)"
check "unverified version keeps state unverified" "unverified" "$(printf '%s' "$STATUS3" | python3 -c 'import json,sys; print(json.load(sys.stdin)["integration"]["State"])')"

log "detach refuses drift and preserves the user's edit"
cp "$CFG" "$WORK/user-config"
set +e
"$BIN/keykoi" --json integration detach --profile aws-cli-helper >"$WORK/detach.out" 2>"$WORK/detach.err"
DETACH_EXIT=$?
set -e
check "detach fails on drift" "1" "$DETACH_EXIT"
check "detach names drift and the affected setting" "yes" "$(grep -Fq 'CONFIG_DRIFT' "$WORK/detach.err" && grep -Fq '[profile keykoi] credential_process' "$WORK/detach.err" && echo yes || echo no)"
check "detach preserves the user's edit" "yes" "$(cmp -s "$CFG" "$WORK/user-config" && echo yes || echo no)"

log "detach restores pre-attach configuration after the managed value is restored"
python3 - "$CFG" "$ATTACHED_VALUE" <<'PY'
from pathlib import Path
import sys

config = Path(sys.argv[1])
lines = config.read_text().splitlines(keepends=True)
config.write_text("".join(sys.argv[2] + "\n" if line.startswith("credential_process = user-command #") else line for line in lines))
PY
"$BIN/keykoi" --json integration detach --profile aws-cli-helper >/dev/null
check "managed field removed" "0" "$(grep -c 'credential_process' "$CFG" || true)"
check "unrelated profile survives detach" "1" "$(grep -c 'region = eu-west-1' "$CFG" | tr -d ' ')"
check "integration record removed" "0" "$("$BIN/keykoi" --json integration list | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"

python3 - "$OUT_DIR/result.json" "$TOOL_VERSION" "${CHECKS[@]}" <<'PY'
import json, sys
out = {"phase": "p1-integration", "environment": {"os": "macOS", "tool_version": sys.argv[2]}, "checks": []}
for raw in sys.argv[3:]:
    st, name, detail = raw.split("|", 2)
    out["checks"].append({"status": st, "name": name, "detail": detail})
out["summary"] = {"total": len(out["checks"]), "failed": sum(1 for c in out["checks"] if c["status"] != "PASS")}
json.dump(out, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
print(f"checks={out['summary']['total']} failed={out['summary']['failed']}")
PY
grep -q '"failed": 0' "$OUT_DIR/result.json" || { log "integration acceptance FAILED"; exit 1; }
log "P1 integration acceptance PASSED"
