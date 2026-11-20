#!/usr/bin/env bash
# P0 验收：用钥协议、显式 HTTP 网关、真实 Helper 与直连/代理测量。
# 全部使用运行时生成的测试凭证与受控上游；不写入真实业务密钥。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/p0}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-p0.XXXXXX")"
BIN="$WORK/bin"
mkdir -p "$BIN" "$OUT_DIR"

log() { printf '%s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

cleanup() {
  set +e
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  [ -n "${UP_HTTP_PID:-}" ] && kill "$UP_HTTP_PID" 2>/dev/null
  [ -n "${UP_AWS_PID:-}" ] && kill "$UP_AWS_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

cd "$ROOT"
log "building binaries"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/mockupstream" ./tests/fixtures/mockupstream

DATA="$WORK/data"
mkdir -p "$DATA"
export KEYKOI_DATA_DIR="$DATA"

UID_NUM="$(id -u)"
CLIENT_PRINCIPAL="principal_local_$UID_NUM"

# 运行时生成的测试凭证（不使用真实密钥）。
GW_KEY_RAW="$(openssl rand -hex 24)"
GW_KEY="Bearer $GW_KEY_RAW"
AWS_ID="AKIA$(openssl rand -hex 8 | tr 'a-f' 'A-F')"
AWS_SECRET="$(openssl rand -hex 20)"
AWS_SESSION="$(openssl rand -hex 24)"

log "starting controlled upstreams"
"$BIN/mockupstream" --addr 127.0.0.1:0 --expect "$GW_KEY" --addr-file "$WORK/up-http.addr" >"$WORK/up-http.log" 2>&1 &
UP_HTTP_PID=$!
"$BIN/mockupstream" --addr 127.0.0.1:0 --expect "sigv4:$AWS_ID" --addr-file "$WORK/up-aws.addr" >"$WORK/up-aws.log" 2>&1 &
UP_AWS_PID=$!
for i in $(seq 1 50); do [ -s "$WORK/up-http.addr" ] && [ -s "$WORK/up-aws.addr" ] && break; sleep 0.1; done
UP_HTTP="http://$(cat "$WORK/up-http.addr")"
UP_AWS="http://$(cat "$WORK/up-aws.addr")"
log "upstream-http=$UP_HTTP upstream-aws=$UP_AWS"

log "starting keykoid (prototype backend)"
"$BIN/keykoid" --prototype --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for i in $(seq 1 50); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
STATUS_JSON="$("$BIN/keykoi" --json status)"
GATEWAY="$(printf '%s' "$STATUS_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["gateway"])')"
[ -n "$GATEWAY" ] || fail "daemon did not report gateway address"
log "gateway=$GATEWAY"

CHECK_RESULTS=()
check() { # name expected actual
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    CHECK_RESULTS+=("PASS|$name|$actual")
    log "PASS $name"
  else
    CHECK_RESULTS+=("FAIL|$name|expected=$expected actual=$actual")
    log "FAIL $name expected=$expected actual=$actual"
  fi
}

log "seeding credentials, bindings and grants"
GW_CRED="$("$BIN/keykoi" --json credential add --kind api_key --label "p0 gateway key" --field "token=$GW_KEY_RAW")"
AWS_CRED="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "p0 aws key" \
  --field "access_id=$AWS_ID" --field "access_secret=$AWS_SECRET" --field "session_token=$AWS_SESSION")"
"$BIN/keykoi" --json binding add --id bind_p0_http --credential "$GW_CRED" --origin "$UP_HTTP" --route p0-http --scheme bearer >/dev/null
"$BIN/keykoi" --json binding add --id bind_p0_aws --credential "$AWS_CRED" --origin "$UP_AWS" --route p0-aws --scheme bearer >/dev/null
"$BIN/keykoi" --json grant add --principal "$CLIENT_PRINCIPAL" --binding bind_p0_http --mode proxy --auth permanent --max-lease-seconds 600 >/dev/null
"$BIN/keykoi" --json grant add --principal "$CLIENT_PRINCIPAL" --binding bind_p0_aws --mode runtime_delivery --auth permanent --max-lease-seconds 600 >/dev/null

# Helper 用 proxy-only binding 调用必须被拒绝：这是模式越权的负例。
if "$BIN/keykoi" helper aws --binding bind_p0_http >"$WORK/helper-denied.out" 2>"$WORK/helper-denied.err"; then
  DENY_RESULT="allowed"
else
  DENY_RESULT="denied"
fi
check "helper requires runtime_delivery grant" "denied" "$DENY_RESULT"

log "P0.2.1: HTTP 链路"
# 通过 CLI 生成会话令牌：measure 内部会创建；这里用 curl 走显式会话。
TOKEN="$(python3 - "$DATA" <<'PY'
import http.client, socket, json, os, sys
sock = os.path.join(sys.argv[1], "keykoid.sock")
class UHTTP(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("keykoi.local")
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(sock)
c = UHTTP()
c.request("POST", "/v1/sessions", json.dumps({"purpose": "p0-acceptance"}),
          {"Content-Type": "application/json"})
r = c.getresponse()
print(json.loads(r.read())["token"])
PY
)"
[ -n "$TOKEN" ] || fail "could not create session"
printf '%s' "$TOKEN" > "$WORK/session.token"

GW_ECHO="$(curl -sS -H "X-KeyKoi-Session: $TOKEN" "$GATEWAY/gateway/p0-http/echo?a=1&a=2")"
check "gateway injects real credential" "true" "$(printf '%s' "$GW_ECHO" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["matched"]).lower())')"
check "gateway strips internal headers" "0" "$(printf '%s' "$GW_ECHO" | python3 -c 'import json,sys; print(1 if json.load(sys.stdin)["keykoi_header_seen"] else 0)')"
check "gateway preserves duplicate query params" "a=1&a=2" "$(printf '%s' "$GW_ECHO" | python3 -c 'import json,sys; print(json.load(sys.stdin)["query"])')"

UP_STATS="$(curl -sS "$UP_HTTP/stats")"
check "upstream never sees session token" "0" "$(printf '%s' "$UP_STATS" | python3 -c 'import json,sys; print(json.load(sys.stdin)["session_tokens"])')"

NO_TOKEN_CODE="$(curl -sS -o "$WORK/no-token.body" -w '%{http_code}' "$GATEWAY/gateway/p0-http/echo")"
check "request without session rejected" "401" "$NO_TOKEN_CODE"
BAD_ROUTE_CODE="$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOKEN" "$GATEWAY/gateway/unregistered/echo")"
check "unregistered target rejected" "404" "$BAD_ROUTE_CODE"
REDIRECT_CODE="$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOKEN" "$GATEWAY/gateway/p0-http/redirect")"
check "cross-origin redirect not followed" "302" "$REDIRECT_CODE"

log "P0.2.2: 真实 Helper（AWS CLI credential_process）"
AWS_DIR="$WORK/aws"
mkdir -p "$AWS_DIR"
cat > "$AWS_DIR/config" <<EOF
[profile keykoi-p0]
region = us-east-1
credential_process = $BIN/keykoi helper aws --binding bind_p0_aws
EOF
export AWS_CONFIG_FILE="$AWS_DIR/config"
export AWS_SHARED_CREDENTIALS_FILE="$AWS_DIR/credentials"
export AWS_EC2_METADATA_DISABLED=true
export AWS_PAGER=""
export HOME_ORIG="$HOME"

AWS_VERSION="$(aws --version 2>&1 | head -1)"
AWS_OUT="$WORK/aws-sts.out"
AWS_ERR="$WORK/aws-sts.err"
set +e
AWS_CLI_CONFIG_FILE="$AWS_DIR/config" aws --profile keykoi-p0 sts get-caller-identity --endpoint-url "$UP_AWS" >"$AWS_OUT" 2>"$AWS_ERR"
AWS_EXIT=$?
set -e
if grep -q "keykoi-fixture" "$AWS_OUT" 2>/dev/null || grep -q "KEYKOIFIXTURE" "$AWS_OUT" 2>/dev/null; then
  check "aws cli authenticated via helper" "ok" "ok"
else
  check "aws cli authenticated via helper" "ok" "exit=$AWS_EXIT $(tail -2 "$AWS_ERR" | tr '\n' ' ')"
fi
AWS_STATS="$(curl -sS "$UP_AWS/stats")"
check "aws cli signature carries helper credential" "1" "$(printf '%s' "$AWS_STATS" | python3 -c 'import json,sys; print(1 if json.load(sys.stdin)["matched"]>=1 else 0)')"
check "aws cli never sends intermediary token" "0" "$(printf '%s' "$AWS_STATS" | python3 -c 'import json,sys; print(json.load(sys.stdin)["session_tokens"])')"

CACHE_DIR="$HOME/.aws/cli/cache"
CACHE_FILES_BEFORE=$(ls -1 "$CACHE_DIR" 2>/dev/null | wc -l | tr -d ' ')
CACHE_FILES_AFTER=$CACHE_FILES_BEFORE
if [ -d "$CACHE_DIR" ]; then CACHE_FILES_AFTER=$(ls -1 "$CACHE_DIR" | wc -l | tr -d ' '); fi

log "P0.2.3: 直连与代理测量"
"$BIN/keykoi" --json measure --route p0-http --gateway "$GATEWAY" --direct "$UP_HTTP" \
  --path "/echo" --requests 20 --stream --out "$OUT_DIR/measure.json" >/dev/null

read -r PROXY_P50 DIRECT_P50 PROXY_FIRST STREAM_FIRST STREAM_TOTAL <<<"$(python3 - "$OUT_DIR/measure.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
p = d["proxy"]; direct = d["direct"]; ps = d["proxy_stream"]
print(p["ttfb_percentiles_ms"]["p50"], direct["ttfb_percentiles_ms"]["p50"],
      p["first_request_ms"], ps["first_chunk_ms"], ps["total_ms"])
PY
)"
check "proxy p50 recorded" "1" "$(python3 -c "print(1 if float('$PROXY_P50') >= 0 else 0)")"
check "stream first chunk precedes completion" "1" "$(python3 -c "print(1 if float('$STREAM_FIRST') < float('$STREAM_TOTAL') else 0)")"

log "P0 additional: lock rejects new use"
"$BIN/keykoi" --json lock >/dev/null
LOCK_CODE="$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOKEN" "$GATEWAY/gateway/p0-http/echo")"
check "locked vault rejects gateway use" "503" "$LOCK_CODE"

HOST_OS="$(sw_vers -productVersion)"
ARCH="$(uname -m)"
GIT_UNKNOWN="unavailable"

python3 - "$OUT_DIR/result.json" "$AWS_VERSION" "$HOST_OS" "$ARCH" "$PROXY_P50" "$DIRECT_P50" "$STREAM_FIRST" "$STREAM_TOTAL" "$CACHE_DIR" "$CACHE_FILES_BEFORE" "$CACHE_FILES_AFTER" "${CHECK_RESULTS[@]}" <<'PY'
import json, sys
out = {
  "phase": "p0",
  "environment": {
    "os": f"macOS {sys.argv[3]}",
    "arch": sys.argv[4],
    "aws_cli": sys.argv[2],
    "upstream": "tests/fixtures/mockupstream (in-memory, no credential persistence)",
  },
  "measurements": {
    "proxy_ttfb_p50_ms": float(sys.argv[5]),
    "direct_ttfb_p50_ms": float(sys.argv[6]),
    "proxy_stream_first_chunk_ms": float(sys.argv[7]),
    "proxy_stream_total_ms": float(sys.argv[8]),
  },
  "aws_cache": {
    "path": sys.argv[9],
    "files_before_run": int(sys.argv[10]),
    "files_after_run": int(sys.argv[11]),
    "note": "AWS CLI 会把 credential_process 结果写入该缓存目录；这是真实工具行为，属于运行时交付边界。",
  },
  "checks": [],
}
for raw in sys.argv[12:]:
    parts = raw.split("|", 2)
    out["checks"].append({"status": parts[0], "name": parts[1], "detail": parts[2] if len(parts) > 2 else ""})
failed = [c for c in out["checks"] if c["status"] != "PASS"]
out["summary"] = {"total": len(out["checks"]), "failed": len(failed)}
json.dump(out, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
print(f"checks={len(out['checks'])} failed={len(failed)}")
PY

if grep -q '"failed": 0' "$OUT_DIR/result.json"; then
  log "P0 acceptance PASSED"
else
  log "P0 acceptance has failures; see $OUT_DIR/result.json"
  exit 1
fi
