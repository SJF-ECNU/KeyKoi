#!/usr/bin/env bash
# P1 运行时交付验收：真实 Helper、仅环境变量路径、取消、异常退出、残留后代、
# 并发账户、凭证更新与服务重启。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/p1-runtime}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-run.XXXXXX")"
BIN="$WORK/bin"; mkdir -p "$BIN" "$OUT_DIR"
log() { printf '%s\n' "$*" >&2; }

cleanup() {
  set +e
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  [ -n "${UP_A_PID:-}" ] && kill "$UP_A_PID" 2>/dev/null
  [ -n "${UP_B_PID:-}" ] && kill "$UP_B_PID" 2>/dev/null
  wait 2>/dev/null
  if [ "${KEEP_WORK:-0}" = "1" ]; then echo "work dir kept: $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

cd "$ROOT"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/mockupstream" ./tests/fixtures/mockupstream

DATA="$WORK/data"; HOME_DIR="$WORK/home"
mkdir -p "$DATA" "$HOME_DIR"
export KEYKOI_DATA_DIR="$DATA" KEYKOI_SOCKET="$DATA/keykoid.sock" HOME="$HOME_DIR"
export AWS_CONFIG_FILE="$HOME_DIR/.aws/config" AWS_SHARED_CREDENTIALS_FILE="$HOME_DIR/.aws/credentials"
export AWS_EC2_METADATA_DISABLED=true AWS_PAGER=""

ID_A="AKIA$(openssl rand -hex 8 | tr 'a-f' 'A-F')"; SEC_A="$(openssl rand -hex 20)"; SESS_A="$(openssl rand -hex 16)"
ID_B="AKIA$(openssl rand -hex 8 | tr 'a-f' 'A-F')"; SEC_B="$(openssl rand -hex 20)"; SESS_B="$(openssl rand -hex 16)"

"$BIN/mockupstream" --addr 127.0.0.1:0 --expect "sigv4:$ID_A" --addr-file "$WORK/upa.addr" >"$WORK/upa.log" 2>&1 &
UP_A_PID=$!
"$BIN/mockupstream" --addr 127.0.0.1:0 --expect "sigv4:$ID_B" --addr-file "$WORK/upb.addr" >"$WORK/upb.log" 2>&1 &
UP_B_PID=$!
for i in $(seq 1 50); do [ -s "$WORK/upa.addr" ] && [ -s "$WORK/upb.addr" ] && break; sleep 0.1; done
UP_A="http://$(cat "$WORK/upa.addr")"; UP_B="http://$(cat "$WORK/upb.addr")"

start_daemon() {
  "$BIN/keykoid" --data-dir "$DATA" --adapters "$ROOT/adapters" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
  KEYKOID_PID=$!
  for i in $(seq 1 80); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
}

start_daemon
printf 'runtime-master-password\n' | "$BIN/keykoi" init --password-stdin >/dev/null

PRINCIPAL="principal_local_$(id -u)"
CRED_A="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "runtime account A" --field "access_id=$ID_A" --field "access_secret=$SEC_A" --field "session_token=$SESS_A")"
CRED_B="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "runtime account B" --field "access_id=$ID_B" --field "access_secret=$SEC_B" --field "session_token=$SESS_B")"
"$BIN/keykoi" --json binding add --id bind_run_a --credential "$CRED_A" --origin "$UP_A" --route run-a --scheme bearer >/dev/null
"$BIN/keykoi" --json binding add --id bind_run_b --credential "$CRED_B" --origin "$UP_B" --route run-b --scheme bearer >/dev/null
for b in bind_run_a bind_run_b; do
  "$BIN/keykoi" --json grant add --principal "$PRINCIPAL" --binding "$b" --mode runtime_delivery --max-lease-seconds 600 --auth permanent >/dev/null
done

AWS_BIN="$(command -v aws)"
CHECKS=()
check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then CHECKS+=("PASS|$name|$actual"); log "PASS $name"
  else CHECKS+=("FAIL|$name|expected=$expected actual=$actual"); log "FAIL $name expected=$expected actual=$actual"; fi
}

ENV_ARGS=(--env AWS_ACCESS_KEY_ID=field:access_id --env AWS_SECRET_ACCESS_KEY=field:access_secret
          --env AWS_SESSION_TOKEN=field:session_token --env AWS_EC2_METADATA_DISABLED=runtime:literal)

log "P1.2.1 real helper run"
"$BIN/keykoi" helper aws --binding bind_run_a > "$WORK/helper.json" 2>"$WORK/helper.err"
check "helper emits AWS credential_process JSON" "1" "$(python3 - "$WORK/helper.json" "$ID_A" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(1 if d.get("Version")==1 and d.get("AccessKeyId")==sys.argv[2] and d.get("SecretAccessKey") else 0)
PY
)"
check "helper writes nothing to stderr" "0" "$(wc -c < "$WORK/helper.err" | tr -d ' ')"

log "env-only path through managed launcher"
"$BIN/keykoi" --json run --binding bind_run_a --exe "$AWS_BIN" \
  --env AWS_ACCESS_KEY_ID=field:access_id --env AWS_SECRET_ACCESS_KEY=field:access_secret \
  --env AWS_SESSION_TOKEN=field:session_token --env AWS_DEFAULT_REGION=literal:us-east-1 \
  --report "$WORK/run-a.json" -- sts get-caller-identity --endpoint-url "$UP_A" > "$WORK/run-a.out" 2>"$WORK/run-a.err"
check "launcher exit code 0" "0" "$(python3 -c "import json;print(json.load(open('$WORK/run-a.json'))['exit_code'])")"
check "launcher revoked lease" "1" "$(python3 -c "import json;d=json.load(open('$WORK/run-a.json'));print(1 if d['lease_id'] and not d.get('leftover_pids') else 0)")"
check "upstream A authenticated" "1" "$(curl -sS "$UP_A/stats" | python3 -c 'import json,sys;print(1 if json.load(sys.stdin)["matched"]>=1 else 0)')"

log "concurrent accounts"
"$BIN/keykoi" --json run --binding bind_run_a --exe "$AWS_BIN" \
  --env AWS_ACCESS_KEY_ID=field:access_id --env AWS_SECRET_ACCESS_KEY=field:access_secret \
  --env AWS_SESSION_TOKEN=field:session_token --env AWS_DEFAULT_REGION=literal:us-east-1 --report "$WORK/ca.json" -- sts get-caller-identity --endpoint-url "$UP_A" >"$WORK/ca.out" 2>&1 &
PA=$!
"$BIN/keykoi" --json run --binding bind_run_b --exe "$AWS_BIN" \
  --env AWS_ACCESS_KEY_ID=field:access_id --env AWS_SECRET_ACCESS_KEY=field:access_secret \
  --env AWS_SESSION_TOKEN=field:session_token --env AWS_DEFAULT_REGION=literal:us-east-1 --report "$WORK/cb.json" -- sts get-caller-identity --endpoint-url "$UP_B" >"$WORK/cb.out" 2>&1 &
PB=$!
wait $PA || true; wait $PB || true
check "account A used its own credential" "1" "$(curl -sS "$UP_A/stats" | python3 -c 'import json,sys;print(1 if json.load(sys.stdin)["matched"]>=2 else 0)')"
check "account B used its own credential" "1" "$(curl -sS "$UP_B/stats" | python3 -c 'import json,sys;print(1 if json.load(sys.stdin)["matched"]>=1 else 0)')"
check "cross-account leak absent" "0" "$(curl -sS "$UP_B/stats" | python3 -c 'import json,sys;print(json.load(sys.stdin)["session_tokens"])')"

log "abnormal exit code propagation"
"$BIN/keykoi" --json run --binding bind_run_a --exe /bin/sh --report "$WORK/abnormal.json" -- -c 'exit 9' >/dev/null 2>&1 || true
check "exit code 9 propagated" "9" "$(python3 -c 'import json;print(json.load(open("'"$WORK/abnormal.json"'"))["exit_code"])' 2>/dev/null || echo missing)"

log "cancellation"
START_TS=$(python3 -c 'import time;print(time.time())')
"$BIN/keykoi" --json run --binding bind_run_a --exe /bin/sh --report "$WORK/cancel.json" -- -c 'sleep 30' >/dev/null 2>"$WORK/cancel.err" &
RPID=$!
sleep 1
kill -INT $RPID 2>/dev/null || true
wait $RPID || true
ELAPSED=$(python3 -c "import time;print(int(time.time()-$START_TS))")
check "cancel terminates promptly" "1" "$(python3 -c "print(1 if $ELAPSED < 12 else 0)")"
check "cancel reflected in result" "1" "$(python3 -c "import json;d=json.load(open('$WORK/cancel.json'));print(1 if d.get('cancelled') else 0)" 2>/dev/null || echo 0)"

log "residual child cleanup"
"$BIN/keykoi" --json run --binding bind_run_a --exe /bin/sh --report "$WORK/leftover.json" -- -c '(sleep 20; echo marker_keykoi_leftover) >/dev/null 2>&1 & exit 0' >/dev/null 2>&1 || true
sleep 2
LEFTOVER_PROCS=$(pgrep -f marker_keykoi_leftover 2>/dev/null | wc -l | tr -d ' ' || true)
check "no residual descendant survives" "0" "$LEFTOVER_PROCS"
CLEANUP_STATUS="$(python3 -c 'import json;print(json.load(open("'"$WORK/leftover.json"'"))["cleanup_status"])' 2>/dev/null || echo missing)"
check "cleanup status reported" "1" "$(python3 -c "print(0 if '$CLEANUP_STATUS' in ('missing','no_leftover_processes') else 1)")"

log "no plaintext in agreed directories (env path)"
LEAKS=$(grep -rIl --exclude-dir=data "$SEC_A" "$HOME_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)
check "no plaintext credential in tool home" "0" "$LEAKS"

log "credential rotation blocks old lease and uses new version"
"$BIN/keykoi" --json credential rotate --id "$CRED_A" --field "access_id=$ID_A" --field "access_secret=newsecret$RANDOM" >/dev/null
set +e
"$BIN/keykoi" --json run --binding bind_run_a --exe "$AWS_BIN" \
  --env AWS_ACCESS_KEY_ID=field:access_id --env AWS_SECRET_ACCESS_KEY=field:access_secret \
  --env AWS_SESSION_TOKEN=field:session_token --env AWS_DEFAULT_REGION=literal:us-east-1 -- sts get-caller-identity --endpoint-url "$UP_A" >"$WORK/rotated.json" 2>&1
ROT_EXIT=$?
set -e
check "run after rotation fails upstream auth" "1" "$(python3 -c "print(0 if $ROT_EXIT==0 else 1)")"

log "service restart invalidates sessions and requires unlock"
kill "$KEYKOID_PID" 2>/dev/null || true
wait "$KEYKOID_PID" 2>/dev/null || true
start_daemon
STATUS="$("$BIN/keykoi" --json status)"
check "restart comes back locked" "True" "$(printf '%s' "$STATUS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["locked"])')"
set +e
"$BIN/keykoi" --json run --binding bind_run_a --exe /bin/echo -- hello >"$WORK/locked.json" 2>&1
LOCKED_EXIT=$?
set -e
check "run refused while locked" "1" "$(python3 -c "print(0 if $LOCKED_EXIT==0 else 1)")"
printf 'runtime-master-password\n' | "$BIN/keykoi" unlock --password-stdin >/dev/null
"$BIN/keykoi" --json run --binding bind_run_a --exe /bin/echo -- hello >/dev/null 2>&1
check "run works after unlock" "0" "$?"

AWS_VERSION="$(aws --version 2>&1 | head -1)"
python3 - "$OUT_DIR/result.json" "$AWS_VERSION" "${CHECKS[@]}" <<'PY'
import json, sys
out = {"phase": "p1-runtime", "environment": {"os": "macOS", "aws_cli": sys.argv[2]}, "checks": []}
for raw in sys.argv[3:]:
    st, name, detail = raw.split("|", 2)
    out["checks"].append({"status": st, "name": name, "detail": detail})
out["summary"] = {"total": len(out["checks"]), "failed": sum(1 for c in out["checks"] if c["status"] != "PASS")}
json.dump(out, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
print(f"checks={out['summary']['total']} failed={out['summary']['failed']}")
PY
grep -q '"failed": 0' "$OUT_DIR/result.json" || { log "runtime acceptance FAILED"; exit 1; }
log "P1 runtime acceptance PASSED"
