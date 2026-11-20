#!/usr/bin/env bash
# P4 专用签名验收：AWS Signature Version 4 请求头签名。
#
# 覆盖：登记协议签名、标准向量、受控上游重算校验、重复查询、大请求、
# 未登记 host / 未授权 binding / 分块与流式标记 / 预签名 / 缺字段拒绝，
# 以及真实 AWS CLI 的签名结构对照。
# 全部凭证在运行时随机生成，不写入日志与验收产物。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/p4-signer}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-p4-signer.XXXXXX")"
BIN="$WORK/bin"
mkdir -p "$BIN" "$OUT_DIR"
chmod 700 "$WORK"

log() { printf '%s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

cleanup() {
  set +e
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  [ -n "${VERIFY_PID:-}" ] && kill "$VERIFY_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

cd "$ROOT"

log "building binaries"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/sigv4verify" ./tests/fixtures/sigv4verify

DATA="$WORK/data"
mkdir -p "$DATA"
chmod 700 "$DATA"
export KEYKOI_DATA_DIR="$DATA"

UID_NUM="$(id -u)"
CLIENT_PRINCIPAL="principal_local_$UID_NUM"
VAULT_PASSWORD="$(openssl rand -hex 16)"

# 运行时生成的测试材料；不来自真实账户。
ACCESS_ID="AKIA$(openssl rand -hex 8 | tr 'a-f' 'A-F')"
ACCESS_SECRET="$(openssl rand -hex 20)"
SESSION_TOKEN="$(openssl rand -hex 24)"
INCOMPLETE_ID="AKIA$(openssl rand -hex 8 | tr 'a-f' 'A-F')"
INCOMPLETE_SECRET="$(openssl rand -hex 20)"

export SIGV4_ACCESS_ID="$ACCESS_ID"
export SIGV4_ACCESS_SECRET="$ACCESS_SECRET"
export SIGV4_SESSION_TOKEN="$SESSION_TOKEN"
export SIGV4_REGION="us-east-1"
export SIGV4_SERVICE="s3"

# 真实 AWS CLI 只对受控本机上游签名，不访问公网。
export AWS_ACCESS_KEY_ID="$ACCESS_ID"
export AWS_SECRET_ACCESS_KEY="$ACCESS_SECRET"
export AWS_SESSION_TOKEN="$SESSION_TOKEN"
export AWS_EC2_METADATA_DISABLED=true
export AWS_PAGER=""
mkdir -p "$WORK/aws"
: > "$WORK/aws/config"
: > "$WORK/aws/credentials"
export AWS_CONFIG_FILE="$WORK/aws/config"
export AWS_SHARED_CREDENTIALS_FILE="$WORK/aws/credentials"

log "starting controlled sigv4 verification upstream"
"$BIN/sigv4verify" --addr 127.0.0.1:0 --addr-file "$WORK/verify.addr" >"$WORK/verify.log" 2>&1 &
VERIFY_PID=$!
for i in $(seq 1 50); do [ -s "$WORK/verify.addr" ] && break; sleep 0.1; done
[ -s "$WORK/verify.addr" ] || fail "verification upstream did not report an address"
VERIFY="http://$(cat "$WORK/verify.addr")"
log "verification upstream: $VERIFY"

log "starting keykoid (encrypted vault backend)"
"$BIN/keykoid" --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for i in $(seq 1 50); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
"$BIN/keykoi" status >/dev/null 2>&1 || fail "keykoid did not start"
printf '%s\n' "$VAULT_PASSWORD" | "$BIN/keykoi" init --password-stdin >/dev/null
log "vault initialized"

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

log "seeding runtime credentials and bindings"
CRED_MAIN="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "p4 sigv4 fixture" \
  --field "access_id=$ACCESS_ID" --field "access_secret=$ACCESS_SECRET" --field "session_token=$SESSION_TOKEN")"
# 缺陷 33：静态 AccessKey（没有 session_token）本身可以签名，不再是"不完整"。
# 真正不完整的是缺少 access_secret。
CRED_INCOMPLETE="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "p4 incomplete fixture" \
  --field "access_id=$INCOMPLETE_ID")"
CRED_STATIC="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "p4 static access key" \
  --field "access_id=$INCOMPLETE_ID" --field "access_secret=$INCOMPLETE_SECRET")"
[ -n "$CRED_MAIN" ] && [ -n "$CRED_INCOMPLETE" ] || fail "credential creation failed"

admin_post() { # path json-file
  python3 - "$DATA" "$1" "$2" <<'PY'
import http.client, json, os, socket, sys
data, path, body_path = sys.argv[1], sys.argv[2], sys.argv[3]
token = open(os.path.join(data, "admin.token")).read().strip()
body = json.load(open(body_path))

class UnixHTTP(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("keykoi.local")
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(os.path.join(data, "keykoid.sock"))

conn = UnixHTTP()
conn.request("POST", path, json.dumps(body),
             {"Content-Type": "application/json", "X-KeyKoi-Admin": token})
resp = conn.getresponse()
payload = resp.read().decode()
if resp.status >= 400:
    sys.stderr.write(payload + "\n")
    sys.exit(1)
PY
}

register_binding() { # id credential adapter_id origin allowed_path
  local id="$1" cred="$2" adapter="$3" origin="$4" path="$5"
  python3 - "$WORK/binding.json" "$id" "$cred" "$adapter" "$origin" "$path" <<'PY'
import json, sys
path, bid, cred, adapter, origin, allowed = sys.argv[1:7]
body = {
    "id": bid, "credential_id": cred, "upstream_origin": origin,
    "route": "p4-" + bid, "auth_scheme": "api_key",
    "allowed_paths": [allowed], "status": "active",
}
if adapter:
    body["adapter_id"] = adapter
json.dump(body, open(path, "w"))
PY
  admin_post /v1/bindings "$WORK/binding.json"
}

register_binding "bind_p4_sigv4" "$CRED_MAIN" "aws-sigv4/us-east-1/s3" "$VERIFY" "/kk/"
register_binding "bind_p4_nogrant" "$CRED_MAIN" "aws-sigv4/us-east-1/s3" "$VERIFY" "/kk/"
register_binding "bind_p4_incomplete" "$CRED_INCOMPLETE" "aws-sigv4/us-east-1/s3" "$VERIFY" "/kk/"
register_binding "bind_p4_static" "$CRED_STATIC" "aws-sigv4/us-east-1/s3" "$VERIFY" "/kk/"
register_binding "bind_p4_noadapter" "$CRED_MAIN" "" "$VERIFY" "/kk/"

for binding in bind_p4_sigv4 bind_p4_incomplete bind_p4_static bind_p4_noadapter; do
  "$BIN/keykoi" --json grant add --principal "$CLIENT_PRINCIPAL" --binding "$binding" \
    --mode sign --auth permanent --max-lease-seconds 600 >/dev/null
done

# 受控上游重算签名所需的重放脚本。
cat > "$WORK/replay.py" <<'PY'
import http.client, json, sys, urllib.parse
url, header_path, method = sys.argv[1], sys.argv[2], sys.argv[3]
body = b""
if len(sys.argv) > 4 and sys.argv[4]:
    body = open(sys.argv[4], "rb").read()
headers = json.load(open(header_path))
# 调用方自己的请求头（Range、Content-Type 等）也参与签名，重放时要一并发送。
if len(sys.argv) > 5 and sys.argv[5]:
    headers.update(json.loads(sys.argv[5]))
headers["User-Agent"] = "keykoi-acceptance/1.0"
parts = urllib.parse.urlsplit(url)
conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=30)
target = parts.path + ("?" + parts.query if parts.query else "")
conn.request(method, target, body=body, headers=headers)
resp = conn.getresponse()
data = resp.read().decode(errors="replace")
sys.stdout.write(json.dumps({"status": resp.status, "body": data}))
PY

log "P4.2: signer unit vectors"
set +e
go test ./internal/signer/ >"$WORK/gotest.log" 2>&1
GOTEST_RC=$?
set -e
check "AWS SigV4 standard vectors (go test ./internal/signer)" "0" "$GOTEST_RC"

log "P4.2: authorized request signature"
URL_DUP_QUERY="$VERIFY/kk/object.txt?versionId=2&versionId=1"
"$BIN/keykoi" sign aws-sigv4 --binding bind_p4_sigv4 --method GET \
  --url "$URL_DUP_QUERY" --header "Range: bytes=0-9" \
  --out "$WORK/headers-get.json" 2>"$WORK/sign-get.err"

check "signature headers emitted" "ok" "$(python3 - "$WORK/headers-get.json" <<'PY'
import json, sys
h = json.load(open(sys.argv[1]))
auth = h.get("Authorization", "")
ok = auth.startswith("AWS4-HMAC-SHA256 Credential=") and "SignedHeaders=" in auth and "Signature=" in auth
ok = ok and h.get("X-Amz-Date") and h.get("X-Amz-Content-Sha256") and h.get("X-Amz-Security-Token")
print("ok" if ok else "missing")
PY
)"

check "access_secret absent from emitted headers" "absent" "$(python3 - "$WORK/headers-get.json" <<'PY'
import json, os, sys
raw = open(sys.argv[1]).read()
print("present" if os.environ["SIGV4_ACCESS_SECRET"] in raw else "absent")
PY
)"

REPLAY_GET="$(python3 "$WORK/replay.py" "$URL_DUP_QUERY" "$WORK/headers-get.json" GET "" '{"Range":"bytes=0-9"}')"
check "controlled upstream verifies signature" "true" "$(printf '%s' "$REPLAY_GET" | python3 -c 'import json,sys; print(str(json.loads(json.load(sys.stdin)["body"])["verified"]).lower())')"
check "duplicate query preserved and sorted" "versionId=1&versionId=2" "$(printf '%s' "$REPLAY_GET" | python3 -c 'import json,sys; print(json.loads(json.load(sys.stdin)["body"])["canonical_query"])')"

log "P4.2: large request (1 MiB payload, complete SHA-256)"
head -c 1048576 /dev/urandom > "$WORK/payload.bin"
URL_LARGE="$VERIFY/kk/large.bin?partNumber=1"
"$BIN/keykoi" sign aws-sigv4 --binding bind_p4_sigv4 --method PUT \
  --url "$URL_LARGE" --payload-file "$WORK/payload.bin" --header "Content-Type: application/octet-stream" \
  --out "$WORK/headers-put.json" >/dev/null 2>"$WORK/sign-put.err"
REPLAY_PUT="$(python3 "$WORK/replay.py" "$URL_LARGE" "$WORK/headers-put.json" PUT "$WORK/payload.bin" '{"Content-Type":"application/octet-stream"}')"
check "large request signature verified" "true" "$(printf '%s' "$REPLAY_PUT" | python3 -c 'import json,sys; print(str(json.loads(json.load(sys.stdin)["body"])["verified"]).lower())')"

STATS_BEFORE="$(curl -sS "$VERIFY/stats")"
VERIFIED_BEFORE="$(printf '%s' "$STATS_BEFORE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verified"])')"

log "P4.2: out-of-scope requests must produce no signature"
neg() { # name binding expected-code args...
  local name="$1" binding="$2" code="$3"
  shift 3
  local out="$WORK/neg-headers.json"
  rm -f "$out"
  set +e
  "$BIN/keykoi" sign aws-sigv4 --binding "$binding" "$@" --out "$out" >"$WORK/neg.out" 2>"$WORK/neg.err"
  local rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    check "$name" "denied" "allowed"
    return
  fi
  if [ -e "$out" ]; then
    check "$name" "no-headers" "headers-written"
    return
  fi
  if grep -q "$code" "$WORK/neg.err"; then
    check "$name" "denied" "denied"
  else
    check "$name" "denied" "wrong-code:$(tr '\n' ' ' < "$WORK/neg.err" | cut -c1-120)"
  fi
}

neg "unregistered host rejected" bind_p4_sigv4 USE_NOT_ALLOWED \
  --method GET --url "http://127.0.0.1:1/kk/object.txt"
neg "path outside registered prefixes rejected" bind_p4_sigv4 USE_NOT_ALLOWED \
  --method GET --url "$VERIFY/outside/object.txt"
neg "binding without sign grant rejected" bind_p4_nogrant USE_NOT_ALLOWED \
  --method GET --url "$URL_DUP_QUERY"
neg "streaming payload marker rejected" bind_p4_sigv4 ADAPTER_UNSUPPORTED \
  --method PUT --url "$URL_LARGE" --header "x-amz-content-sha256:STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
neg "chunked transfer encoding rejected" bind_p4_sigv4 ADAPTER_UNSUPPORTED \
  --method PUT --url "$URL_LARGE" --header "Transfer-Encoding:chunked"
neg "presigned query rejected" bind_p4_sigv4 ADAPTER_UNSUPPORTED \
  --method GET --url "$VERIFY/kk/object.txt?X-Amz-Signature=deadbeef"
neg "credential without access_secret rejected" bind_p4_incomplete CREDENTIAL_UNAVAILABLE \
  --method GET --url "$URL_DUP_QUERY"
"$BIN/keykoi" sign aws-sigv4 --binding bind_p4_static --method GET --url "$URL_DUP_QUERY" \
  --out "$WORK/headers-static.json" >/dev/null 2>"$WORK/sign-static.err"
STATIC_TOKEN="$(python3 - "$WORK/headers-static.json" <<'PYEOF'
import json, sys
h = json.load(open(sys.argv[1]))
print("present" if h.get("X-Amz-Security-Token") else "absent")
PYEOF
)"
check "static access key signs without a session token" "absent" "$STATIC_TOKEN"
neg "region override rejected" bind_p4_sigv4 ADAPTER_UNSUPPORTED \
  --method GET --url "$URL_DUP_QUERY" --region us-west-2
neg "binding without adapter config rejected" bind_p4_noadapter ADAPTER_UNSUPPORTED \
  --method GET --url "$URL_DUP_QUERY"
neg "unsupported method rejected" bind_p4_sigv4 BAD_REQUEST \
  --method CONNECT --url "$URL_DUP_QUERY"

STATS_AFTER_NEG="$(curl -sS "$VERIFY/stats")"
VERIFIED_AFTER_NEG="$(printf '%s' "$STATS_AFTER_NEG" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verified"])')"
check "rejected requests produced no signature" "$VERIFIED_BEFORE" "$VERIFIED_AFTER_NEG"

log "P4.2: reference request for AWS CLI structure comparison"
URL_REFERENCE="$VERIFY/kk/reference.txt"
"$BIN/keykoi" sign aws-sigv4 --binding bind_p4_sigv4 --method GET \
  --url "$URL_REFERENCE" --out "$WORK/headers-ref.json" >/dev/null 2>"$WORK/sign-ref.err"
REPLAY_REF="$(python3 "$WORK/replay.py" "$URL_REFERENCE" "$WORK/headers-ref.json" GET)"
check "reference request verified for structure comparison" "true" "$(printf '%s' "$REPLAY_REF" | python3 -c 'import json,sys; print(str(json.loads(json.load(sys.stdin)["body"])["verified"]).lower())')"

log "P4.2: real AWS CLI comparison"
AWS_VERSION="$(aws --version 2>&1 | head -1)"
set +e
aws --region us-east-1 --endpoint-url "$VERIFY" s3api list-objects --bucket kk-bucket --prefix x \
  >"$WORK/aws.out" 2>"$WORK/aws.err"
AWS_RC=$?
set -e
check "aws cli signed request accepted by controlled upstream" "0" "$AWS_RC"

set +e
aws --region us-east-1 --endpoint-url "$VERIFY" s3 presign s3://kk-bucket/key.txt --expires-in 300 \
  >"$WORK/presign.url" 2>"$WORK/presign.err"
PRESIGN_RC=$?
set -e
python3 - "$WORK/presign.url" "$WORK/presign.json" "$PRESIGN_RC" <<'PY'
import json, sys, urllib.parse
raw, out_path, rc = sys.argv[1], sys.argv[2], sys.argv[3]
url = open(raw).read().strip() if rc == "0" else ""
names = sorted({k for k, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)})
json.dump({"aws_cli_exit": int(rc), "query_params": names,
           "uses_query_signature": "X-Amz-Signature" in names}, open(out_path, "w"))
PY

STATS="$(curl -sS "$VERIFY/stats")"
printf '%s' "$STATS" > "$WORK/stats.json"
python3 - "$WORK/stats.json" "$WORK/compare.json" <<'PY'
import json, sys
st = json.load(open(sys.argv[1]))
structures = st.get("structures", {})
kk = structures.get("keykoi", {})
aws = structures.get("aws-cli", {})
required = {"host", "x-amz-content-sha256", "x-amz-date", "x-amz-security-token"}

def scope_tail(scope):
    parts = scope.split("/")
    return parts[2:] if len(parts) == 5 else []

match = bool(kk and aws) and (
    kk.get("algorithm") == aws.get("algorithm")
    and scope_tail(kk.get("credential_scope", "")) == scope_tail(aws.get("credential_scope", ""))
    and kk.get("signature_length") == aws.get("signature_length") == 64
    and required.issubset(set(kk.get("signed_headers", [])))
    and required.issubset(set(aws.get("signed_headers", [])))
)
json.dump({
    "signature_structure_match": match,
    "required_headers": sorted(required),
    "keykoi": kk,
    "aws_cli": aws,
    "signed_headers_identical": kk.get("signed_headers") == aws.get("signed_headers"),
    "verified_by_agent": st.get("verified_by_agent", {}),
    "upstream_verified": st.get("verified", 0),
    "upstream_failed": st.get("failed", 0),
}, open(sys.argv[2], "w"))
PY
check "aws cli authorization structure matches keykoi" "true" "$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["signature_structure_match"]).lower())' "$WORK/compare.json")"

mkdir -p "$OUT_DIR"
HOST_OS="$(sw_vers -productVersion)"
ARCH="$(uname -m)"
GO_VERSION="$(go version)"
python3 - "$WORK/env.json" "$HOST_OS" "$ARCH" "$GO_VERSION" "$AWS_VERSION" "$VERIFY" <<'PY'
import json, sys
json.dump({
    "os": "macOS " + sys.argv[2],
    "arch": sys.argv[3],
    "go": sys.argv[4],
    "aws_cli": sys.argv[5],
    "upstream": "tests/fixtures/sigv4verify (independent SigV4 recomputation, no credential persistence)",
    "upstream_addr": sys.argv[6],
}, open(sys.argv[1], "w"))
PY

python3 - "$OUT_DIR/result.json" "$WORK/env.json" "$WORK/compare.json" "$WORK/presign.json" "${CHECK_RESULTS[@]}" <<'PY'
import json, sys
out_path, env_path, compare_path, presign_path = sys.argv[1:5]
env = json.load(open(env_path))
compare = json.load(open(compare_path))
presign = json.load(open(presign_path))
checks = []
for raw in sys.argv[5:]:
    parts = raw.split("|", 2)
    checks.append({"status": parts[0], "name": parts[1], "detail": parts[2] if len(parts) > 2 else ""})
failed = [c for c in checks if c["status"] != "PASS"]
out = {
    "phase": "p4-signer",
    "protocol": {
        "id": "aws-sigv4",
        "algorithm": "AWS4-HMAC-SHA256",
        "methods": ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        "signed_headers": [
            "host", "x-amz-date", "x-amz-content-sha256 (s3)",
            "x-amz-security-token", "whitelisted caller headers",
        ],
        "payload_modes": {
            "single_complete_sha256": True,
            "chunked_or_streaming": False,
            "unsigned_payload": False,
        },
        "presigned_urls": {
            "supported": False,
            "aws_cli_query_params": presign.get("query_params", []),
            "uses_query_signature": presign.get("uses_query_signature", False),
            "reason": "aws-sigv4 签名器只返回请求头签名；预签名 URL 会以查询串授予临时访问，超出 sign 许可边界。",
        },
        "credential": "access_key_pair: access_id/access_secret/session_token，要求同一版本字段完整；adapter_id 形如 aws-sigv4/<region>/<service>",
        "session_token_delivery": "X-Amz-Security-Token 作为 AWS 要求的签名头返回给调用方；只写 0600 文件或 stdout，不进日志与验收产物。",
        "logging": "签名材料不写入日志或审计；access_secret 不出签名器，响应只含签名头与许可元数据。",
    },
    "environment": env,
    "comparisons": compare,
    "checks": checks,
    "summary": {"total": len(checks), "failed": len(failed)},
}
json.dump(out, open(out_path, "w"), indent=2, ensure_ascii=False)
print(f"checks={len(checks)} failed={len(failed)}")
PY

if grep -q '"failed": 0' "$OUT_DIR/result.json"; then
  log "P4 signer acceptance PASSED"
else
  log "P4 signer acceptance has failures; see $OUT_DIR/result.json"
  exit 1
fi
