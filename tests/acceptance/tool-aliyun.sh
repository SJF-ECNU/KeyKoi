#!/usr/bin/env bash
# 真实工具验证：阿里云 CLI（aliyun-cli 3.x）通过 KeyKoi 运行时交付取得凭证。
# 使用受控 HTTPS 上游与本机自签证书；不访问真实阿里云端点。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/tool-aliyun}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-aliyun.XXXXXX")"
BIN="$WORK/bin"; DATA="$WORK/data"; HOME_DIR="$WORK/home"
mkdir -p "$BIN" "$DATA" "$HOME_DIR" "$OUT_DIR"
log() { printf '%s\n' "$*" >&2; }

cleanup() {
  set +e
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  [ -n "${UP_PID:-}" ] && kill "$UP_PID" 2>/dev/null
  wait 2>/dev/null
  if [ "${KEEP_WORK:-0}" = "1" ]; then echo "work dir kept: $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# PATH may start with an already installed KeyKoi shim. Pin the real tool.
if [ -z "${ALIYUN_BIN:-}" ] && command -v brew >/dev/null; then
  ALIYUN_BIN="$(brew --prefix aliyun-cli)/bin/aliyun"
fi
case "${ALIYUN_BIN:-}" in /*) ;; *) log "Set ALIYUN_BIN to the absolute path of the real aliyun CLI"; exit 2 ;; esac
[ -x "$ALIYUN_BIN" ] || { log "aliyun CLI is not executable at $ALIYUN_BIN"; exit 2; }

cd "$ROOT"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/mockupstream" ./tests/fixtures/mockupstream

export KEYKOI_DATA_DIR="$DATA" KEYKOI_SOCKET="$DATA/keykoid.sock" HOME="$HOME_DIR"
# 阿里云 CLI 会继承父进程代理设置；运行时交付使用受控环境，不继承这些变量。

AK="AKID$(openssl rand -hex 8 | tr 'a-f' 'A-F')"
SK="$(openssl rand -hex 20)"
STOK="$(openssl rand -hex 12)"
UP_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"

log "prepare controlled HTTPS upstream (self-signed, test only)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" >/dev/null 2>&1
"$BIN/mockupstream" --addr "127.0.0.1:$UP_PORT" --expect-query "AccessKeyId=$AK" \
  --tls-cert "$WORK/cert.pem" --tls-key "$WORK/key.pem" >"$WORK/up.log" 2>&1 &
UP_PID=$!
for i in $(seq 1 50); do curl -fsS --cacert "$WORK/cert.pem" "https://127.0.0.1:$UP_PORT/stats" >/dev/null 2>&1 && break; sleep 0.1; done
UP="https://127.0.0.1:$UP_PORT"

log "start keykoid and seed the real account shape"
"$BIN/keykoid" --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for i in $(seq 1 80); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
printf 'aliyun-acceptance-password\n' | "$BIN/keykoi" init --password-stdin >/dev/null

PRINCIPAL="principal_local_$(id -u)"
CRED="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "aliyun test account" \
  --field "access_id=$AK" --field "access_secret=$SK" --field "session_token=$STOK")"
"$BIN/keykoi" --json binding add --id bind_aliyun --credential "$CRED" --origin "$UP" --route aliyun-ecs --scheme bearer >/dev/null
"$BIN/keykoi" --json binding add --id bind_aliyun_proxy --credential "$CRED" --origin "$UP" --route aliyun-ecs-proxy --scheme bearer >/dev/null
"$BIN/keykoi" --json grant add --principal "$PRINCIPAL" --binding bind_aliyun --mode runtime_delivery --auth permanent --max-lease-seconds 300 >/dev/null
"$BIN/keykoi" --json grant add --principal "$PRINCIPAL" --binding bind_aliyun_proxy --mode proxy --auth permanent --max-lease-seconds 300 >/dev/null

CHECKS=()
check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then CHECKS+=("PASS|$name|$actual"); log "PASS $name"
  else CHECKS+=("FAIL|$name|expected=$expected actual=$actual"); log "FAIL $name expected=$expected actual=$actual"; fi
}

ALIYUN_VERSION="$("$ALIYUN_BIN" version)"
log "aliyun version: $ALIYUN_VERSION"

log "run real aliyun CLI with KeyKoi-injected environment"
set +e
"$BIN/keykoi" --json run --binding bind_aliyun --exe "$ALIYUN_BIN" \
  --env ALIBABA_CLOUD_ACCESS_KEY_ID=field:access_id \
  --env ALIBABA_CLOUD_ACCESS_KEY_SECRET=field:access_secret \
  --env ALIBABA_CLOUD_SECURITY_TOKEN=field:session_token \
  --report "$WORK/run.json" -- --config-path "$WORK/no-config.json" ecs DescribeRegions \
  --endpoint "127.0.0.1:$UP_PORT" --region cn-hangzhou --skip-secure-verify >"$WORK/run.out" 2>"$WORK/run.err"
RUN_EXIT=$?
set -e
check "aliyun command exits 0" "0" "$RUN_EXIT"
check "aliyun received a well-formed API response" "yes" "$(grep -q "DescribeRegionsResponse" "$WORK/run.out" && echo yes || echo no)"
DURATION_MS="$(python3 -c "import json;print(json.load(open('$WORK/run.json'))['duration_ms'])" 2>/dev/null || echo 0)"
CLEANUP="$(python3 -c "import json;print(json.load(open('$WORK/run.json'))['cleanup_status'])" 2>/dev/null || echo missing)"
check "managed run reports clean process tree" "no_leftover_processes" "$CLEANUP"
check "lease revoked after run" "1" "$(python3 -c "import json;d=json.load(open('$WORK/run.json'));print(1 if d['lease_id'] else 0)" 2>/dev/null || echo 0)"

STATS="$(curl -sS --cacert "$WORK/cert.pem" "$UP/stats")"
stat() { printf '%s' "$STATS" | python3 -c "import json,sys;print(json.load(sys.stdin)[\"$1\"])"; }
check "upstream saw AccessKeyId from KeyKoi (value matched)" "1" "$(stat query_matched)"
check "upstream saw the request action" "DescribeRegions" "$(stat last_action)"
check "aliyun sent a signature field" "True" "$(stat signature_seen)"
check "session token field delivered as SecurityToken" "True" "$(stat security_token_seen)"
check "KeyKoi intermediary token never reached upstream" "0" "$(stat session_tokens)"

log "negative: proxy-only grant cannot be used for runtime delivery"
set +e
"$BIN/keykoi" --json run --binding bind_aliyun_proxy --exe /bin/echo -- hello >"$WORK/proxy.out" 2>"$WORK/proxy.err"
PROXY_EXIT=$?
set -e
check "runtime delivery without grant is refused" "1" "$(python3 -c "print(0 if $PROXY_EXIT==0 else 1)")"

log "negative: locked vault refuses delivery"
"$BIN/keykoi" --json lock >/dev/null
set +e
"$BIN/keykoi" --json run --binding bind_aliyun --exe /bin/echo -- hello >"$WORK/locked.out" 2>&1
LOCKED_EXIT=$?
set -e
check "locked vault refuses new use" "1" "$(python3 -c "print(0 if $LOCKED_EXIT==0 else 1)")"

log "no plaintext credential left in the tool home"
LEAKS="$(grep -rIl "$SK" "$HOME_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)"
check "tool home has no plaintext access secret" "0" "$LEAKS"

python3 - "$OUT_DIR/result.json" "$ALIYUN_VERSION" "$DURATION_MS" "${CHECKS[@]}" <<'PY'
import json, sys
out = {
  "phase": "tool-aliyun",
  "environment": {
    "os": "macOS 27.0 arm64",
    "tool": sys.argv[2],
    "upstream": "controlled HTTPS mock (self-signed test cert, no real Alibaba Cloud endpoint)",
    "delivery": "runtime_delivery via keykoi run environment injection",
    "caveat": "aliyun CLI --skip-secure-verify is used only to trust the controlled test certificate; KeyKoi 自身的上游校验未关闭。",
  },
  "measurements": {"run_duration_ms": int(sys.argv[3])},
  "checks": [],
}
for raw in sys.argv[4:]:
    st, name, detail = raw.split("|", 2)
    out["checks"].append({"status": st, "name": name, "detail": detail})
out["summary"] = {"total": len(out["checks"]), "failed": sum(1 for c in out["checks"] if c["status"] != "PASS")}
json.dump(out, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
print(f"checks={out['summary']['total']} failed={out['summary']['failed']}")
PY
grep -q '"failed": 0' "$OUT_DIR/result.json" || { log "aliyun acceptance FAILED"; exit 1; }
log "aliyun acceptance PASSED"
