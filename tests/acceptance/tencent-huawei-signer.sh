#!/usr/bin/env bash
# 腾讯云 TC3-HMAC-SHA256 与华为云 SDK-HMAC-SHA256 请求签名验收。
#
# 覆盖：按 Binding.AdapterID 前缀分派、官方文档向量、受控校验上游独立重算、
# 有会话令牌/无会话令牌、GET 查询串、POST payload、越界 host/path、
# 无 sign 许可、错误 region、不支持的 method、协议与登记不符。
# 全部凭证在运行时随机生成，不写入日志与验收产物。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/tencent-huawei-signer}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-cloud-signer.XXXXXX")"
BIN="$WORK/bin"
mkdir -p "$BIN" "$OUT_DIR"
chmod 700 "$WORK"

log() { printf '%s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

cleanup() {
  set +e
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  [ -n "${TC3_VERIFY_PID:-}" ] && kill "$TC3_VERIFY_PID" 2>/dev/null
  [ -n "${HW_VERIFY_PID:-}" ] && kill "$HW_VERIFY_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

cd "$ROOT"

log "building binaries"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/cloudsignverify" ./tests/fixtures/cloudsignverify

DATA="$WORK/data"
mkdir -p "$DATA"
chmod 700 "$DATA"
export KEYKOI_DATA_DIR="$DATA"

UID_NUM="$(id -u)"
CLIENT_PRINCIPAL="principal_local_$UID_NUM"
VAULT_PASSWORD="$(openssl rand -hex 16)"

# 运行时生成的测试材料；不来自真实账户。
TEN_ACCESS_ID="AKID$(openssl rand -hex 8 | tr 'a-f' 'A-F')"
TEN_ACCESS_SECRET="$(openssl rand -hex 20)"
TEN_SESSION_TOKEN="$(openssl rand -hex 24)"
HW_ACCESS_ID="HWAK$(openssl rand -hex 8 | tr 'a-f' 'A-F')"
HW_ACCESS_SECRET="$(openssl rand -hex 20)"
HW_SESSION_TOKEN="$(openssl rand -hex 24)"
INCOMPLETE_ID="AKID$(openssl rand -hex 8 | tr 'a-f' 'A-F')"
INCOMPLETE_SECRET="$(openssl rand -hex 20)"

export TEN_ACCESS_SECRET
export HW_ACCESS_SECRET

TEN_REGION="ap-guangzhou"
TEN_SERVICE="cvm"
HW_REGION="cn-north-4"
HW_SERVICE="ecs"

printf '%s' '{"Limit": 1, "Filters": [{"Values": ["\u672a\u547d\u540d"], "Name": "instance-name"}]}' > "$WORK/payload.json"

start_verifier() { # mode env-prefix
  local mode="$1"; shift
  local addr_file="$WORK/verify-$mode.addr"
  env "$@" "$BIN/cloudsignverify" --mode "$mode" --addr 127.0.0.1:0 --addr-file "$addr_file" \
    >"$WORK/verify-$mode.log" 2>&1 &
  local pid=$!
  for i in $(seq 1 50); do [ -s "$addr_file" ] && break; sleep 0.1; done
  [ -s "$addr_file" ] || fail "$mode verification upstream did not report an address"
  printf '%s' "$pid"
}

log "starting controlled verification upstreams"
TC3_VERIFY_PID="$(start_verifier tc3 \
  CLOUDSIGN_ACCESS_ID="$TEN_ACCESS_ID" \
  CLOUDSIGN_ACCESS_SECRET="$TEN_ACCESS_SECRET" \
  CLOUDSIGN_SESSION_TOKEN="$TEN_SESSION_TOKEN" \
  CLOUDSIGN_SERVICE="$TEN_SERVICE" \
  CLOUDSIGN_REGION="$TEN_REGION")"
HW_VERIFY_PID="$(start_verifier huawei \
  CLOUDSIGN_ACCESS_ID="$HW_ACCESS_ID" \
  CLOUDSIGN_ACCESS_SECRET="$HW_ACCESS_SECRET" \
  CLOUDSIGN_SESSION_TOKEN="$HW_SESSION_TOKEN" \
  CLOUDSIGN_SERVICE="$HW_SERVICE" \
  CLOUDSIGN_REGION="$HW_REGION")"
TC3_VERIFY="http://$(cat "$WORK/verify-tc3.addr")"
HW_VERIFY="http://$(cat "$WORK/verify-huawei.addr")"
log "tc3 verification upstream: $TC3_VERIFY"
log "huawei verification upstream: $HW_VERIFY"

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
CRED_TEN="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "tencent tc3 fixture" \
  --field "access_id=$TEN_ACCESS_ID" --field "access_secret=$TEN_ACCESS_SECRET" \
  --field "session_token=$TEN_SESSION_TOKEN")"
CRED_HW="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "huawei aksk fixture" \
  --field "access_id=$HW_ACCESS_ID" --field "access_secret=$HW_ACCESS_SECRET" \
  --field "session_token=$HW_SESSION_TOKEN")"
# 缺陷 33：静态 AccessKey（没有 session_token）可以签名；真正不完整的是缺少 access_secret。
CRED_INCOMPLETE="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "cloud incomplete fixture" \
  --field "access_id=$INCOMPLETE_ID")"
CRED_STATIC="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "cloud static access key" \
  --field "access_id=$INCOMPLETE_ID" --field "access_secret=$INCOMPLETE_SECRET")"
[ -n "$CRED_TEN" ] && [ -n "$CRED_HW" ] && [ -n "$CRED_INCOMPLETE" ] || fail "credential creation failed"

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
    "route": "cloud-" + bid, "auth_scheme": "api_key",
    "allowed_paths": [allowed], "status": "active",
}
if adapter:
    body["adapter_id"] = adapter
json.dump(body, open(path, "w"))
PY
  admin_post /v1/bindings "$WORK/binding.json"
}

register_binding "bind_th_signer" "$CRED_TEN" "tencent-tc3/$TEN_REGION/$TEN_SERVICE" "$TC3_VERIFY" "/"
register_binding "bind_th_nogrant" "$CRED_TEN" "tencent-tc3/$TEN_REGION/$TEN_SERVICE" "$TC3_VERIFY" "/"
register_binding "bind_th_incomplete" "$CRED_INCOMPLETE" "tencent-tc3/$TEN_REGION/$TEN_SERVICE" "$TC3_VERIFY" "/"
register_binding "bind_th_static" "$CRED_STATIC" "tencent-tc3/$TEN_REGION/$TEN_SERVICE" "$TC3_VERIFY" "/"
register_binding "bind_hw_signer" "$CRED_HW" "huawei-aksk/$HW_REGION/$HW_SERVICE" "$HW_VERIFY" "/kk/"

for binding in bind_th_signer bind_th_incomplete bind_th_static bind_hw_signer; do
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
# 调用方自己的请求头（Content-Type 等）也参与签名，重放时要一并发送。
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

log "P4.3: signer unit vectors (腾讯云/华为云官方文档向量)"
set +e
go test ./internal/signer/ >"$WORK/gotest.log" 2>&1
GOTEST_RC=$?
set -e
check "Tencent TC3 + Huawei AK/SK vectors (go test ./internal/signer)" "0" "$GOTEST_RC"

log "P4.3: TC3 POST signature with X-TC-Action and session token"
TC3_POST_URL="$TC3_VERIFY/"
"$BIN/keykoi" sign tencent-tc3 --binding bind_th_signer --method POST --url "$TC3_POST_URL" \
  --header "content-type: application/json; charset=utf-8" --action DescribeInstances \
  --payload-file "$WORK/payload.json" --out "$WORK/th-post.json" 2>"$WORK/sign-th-post.err"

check "tc3 signature headers emitted" "ok" "$(python3 - "$WORK/th-post.json" <<'PY'
import json, sys
h = json.load(open(sys.argv[1]))
auth = h.get("Authorization", "")
ok = auth.startswith("TC3-HMAC-SHA256 Credential=") and "SignedHeaders=content-type;host;x-tc-action" in auth
ok = ok and "Signature=" in auth and h.get("X-TC-Timestamp") and h.get("X-TC-Action") == "DescribeInstances"
ok = ok and h.get("X-TC-Token")
print("ok" if ok else "missing")
PY
)"

check "tc3 secret key absent from emitted headers" "absent" "$(python3 - "$WORK/th-post.json" <<'PY'
import json, os, sys
raw = open(sys.argv[1]).read()
print("present" if os.environ["TEN_ACCESS_SECRET"] in raw else "absent")
PY
)"

REPLAY_TC3_POST="$(python3 "$WORK/replay.py" "$TC3_POST_URL" "$WORK/th-post.json" POST "$WORK/payload.json" \
  '{"content-type":"application/json; charset=utf-8"}')"
check "tc3 controlled upstream verifies signature" "True" "$(printf '%s' "$REPLAY_TC3_POST" | python3 -c 'import json,sys; print(json.loads(json.load(sys.stdin)["body"])["verified"])')"
check "tc3 canonical URI fixed to /" "/" "$(printf '%s' "$REPLAY_TC3_POST" | python3 -c 'import json,sys; print(json.loads(json.load(sys.stdin)["body"])["canonical_uri"])')"
check "tc3 signed headers include x-tc-action" "content-type;host;x-tc-action" "$(printf '%s' "$REPLAY_TC3_POST" | python3 -c 'import json,sys; print(";".join(json.loads(json.load(sys.stdin)["body"])["structure"]["signed_headers"]))')"

log "P4.3: TC3 GET signature with query string"
TC3_GET_URL="$TC3_VERIFY/?Limit=10&Offset=0"
"$BIN/keykoi" sign tencent-tc3 --binding bind_th_signer --method GET --url "$TC3_GET_URL" \
  --header "content-type: application/x-www-form-urlencoded" --action DescribeInstances \
  --out "$WORK/th-get.json" 2>"$WORK/sign-th-get.err"
REPLAY_TC3_GET="$(python3 "$WORK/replay.py" "$TC3_GET_URL" "$WORK/th-get.json" GET "" \
  '{"content-type":"application/x-www-form-urlencoded"}')"
check "tc3 GET signature verified with sorted query" "True" "$(printf '%s' "$REPLAY_TC3_GET" | python3 -c 'import json,sys; print(json.loads(json.load(sys.stdin)["body"])["verified"])')"
check "tc3 GET canonical query sorted" "Limit=10&Offset=0" "$(printf '%s' "$REPLAY_TC3_GET" | python3 -c 'import json,sys; print(json.loads(json.load(sys.stdin)["body"])["canonical_query"])')"

log "P4.3: Huawei GET signature"
HW_GET_URL="$HW_VERIFY/kk/v2/proj/servers?name=web&limit=1"
"$BIN/keykoi" sign huawei-aksk --binding bind_hw_signer --method GET --url "$HW_GET_URL" \
  --header "Content-Type: application/json" --out "$WORK/hw-get.json" 2>"$WORK/sign-hw-get.err"
check "huawei signature headers emitted" "ok" "$(python3 - "$WORK/hw-get.json" <<'PY'
import json, sys
h = json.load(open(sys.argv[1]))
auth = h.get("Authorization", "")
ok = auth.startswith("SDK-HMAC-SHA256 Access=") and "SignedHeaders=content-type;host;x-sdk-date" in auth
ok = ok and "Signature=" in auth and h.get("X-Sdk-Date") and h.get("X-Security-Token")
print("ok" if ok else "missing")
PY
)"
check "huawei secret key absent from emitted headers" "absent" "$(python3 - "$WORK/hw-get.json" <<'PY'
import json, os, sys
raw = open(sys.argv[1]).read()
print("present" if os.environ["HW_ACCESS_SECRET"] in raw else "absent")
PY
)"
REPLAY_HW_GET="$(python3 "$WORK/replay.py" "$HW_GET_URL" "$WORK/hw-get.json" GET "" '{"content-type":"application/json"}')"
check "huawei GET signature verified by controlled upstream" "True" "$(printf '%s' "$REPLAY_HW_GET" | python3 -c 'import json,sys; print(json.loads(json.load(sys.stdin)["body"])["verified"])')"
check "huawei canonical URI ends with /" "/kk/v2/proj/servers/" "$(printf '%s' "$REPLAY_HW_GET" | python3 -c 'import json,sys; print(json.loads(json.load(sys.stdin)["body"])["canonical_uri"])')"

log "P4.3: Huawei POST signature with payload"
HW_POST_URL="$HW_VERIFY/kk/v3.0/OS-USER/users"
"$BIN/keykoi" sign huawei-aksk --binding bind_hw_signer --method POST --url "$HW_POST_URL" \
  --header "Content-Type: application/json" --payload-file "$WORK/payload.json" \
  --out "$WORK/hw-post.json" 2>"$WORK/sign-hw-post.err"
REPLAY_HW_POST="$(python3 "$WORK/replay.py" "$HW_POST_URL" "$WORK/hw-post.json" POST "$WORK/payload.json" '{"content-type":"application/json"}')"
check "huawei POST signature verified with payload digest" "True" "$(printf '%s' "$REPLAY_HW_POST" | python3 -c 'import json,sys; print(json.loads(json.load(sys.stdin)["body"])["verified"])')"
check "huawei payload digest covers the sent body" "$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$WORK/payload.json")" \
  "$(printf '%s' "$REPLAY_HW_POST" | python3 -c 'import json,sys; print(json.loads(json.load(sys.stdin)["body"])["structure"]["payload_sha256"])')"

TC3_STATS_BEFORE="$(curl -sS "$TC3_VERIFY/stats")"
TC3_VERIFIED_BEFORE="$(printf '%s' "$TC3_STATS_BEFORE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verified"])')"
HW_STATS_BEFORE="$(curl -sS "$HW_VERIFY/stats")"
HW_VERIFIED_BEFORE="$(printf '%s' "$HW_STATS_BEFORE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verified"])')"

log "P4.3: out-of-scope requests must produce no signature"
neg() { # name binding expected-code protocol args...
  local name="$1" binding="$2" code="$3" protocol="$4"
  shift 4
  local out="$WORK/neg-headers.json"
  rm -f "$out"
  set +e
  "$BIN/keykoi" sign "$protocol" --binding "$binding" "$@" --out "$out" >"$WORK/neg.out" 2>"$WORK/neg.err"
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
    check "$name" "denied" "wrong-code:$(tr '\n' ' ' < "$WORK/neg.err" | cut -c1-140)"
  fi
}

neg "tc3 unregistered host rejected" bind_th_signer USE_NOT_ALLOWED tencent-tc3 \
  --method POST --url "http://127.0.0.1:1/" --header "content-type: application/json"
neg "tc3 path outside the fixed canonical URI rejected" bind_th_signer ADAPTER_UNSUPPORTED tencent-tc3 \
  --method POST --url "$TC3_VERIFY/v1/instances" --header "content-type: application/json"
neg "tc3 binding without sign grant rejected" bind_th_nogrant USE_NOT_ALLOWED tencent-tc3 \
  --method POST --url "$TC3_POST_URL" --header "content-type: application/json"
neg "tc3 wrong region override rejected" bind_th_signer ADAPTER_UNSUPPORTED tencent-tc3 \
  --method POST --url "$TC3_POST_URL" --header "content-type: application/json" --region ap-beijing
neg "tc3 post with query string rejected" bind_th_signer ADAPTER_UNSUPPORTED tencent-tc3 \
  --method POST --url "$TC3_VERIFY/?Limit=10" --header "content-type: application/json"
neg "tc3 unsupported method rejected" bind_th_signer ADAPTER_UNSUPPORTED tencent-tc3 \
  --method PATCH --url "$TC3_POST_URL" --header "content-type: application/json"
neg "credential without access_secret rejected" bind_th_incomplete CREDENTIAL_UNAVAILABLE tencent-tc3 \
  --method POST --url "$TC3_POST_URL" --header "content-type: application/json"
"$BIN/keykoi" sign tencent-tc3 --binding bind_th_static --method POST --url "$TC3_POST_URL" \
  --header "content-type: application/json" --out "$WORK/th-static.json" 2>"$WORK/sign-th-static.err"
STATIC_TC_TOKEN="$(python3 - "$WORK/th-static.json" <<'PYEOF'
import json, sys
h = json.load(open(sys.argv[1]))
print("present" if h.get("X-TC-Token") else "absent")
PYEOF
)"
check "static access key signs without an X-TC-Token" "absent" "$STATIC_TC_TOKEN"
neg "protocol does not match the registered adapter" bind_th_signer ADAPTER_UNSUPPORTED aws-sigv4 \
  --method GET --url "$TC3_POST_URL"
neg "huawei path outside registered prefixes rejected" bind_hw_signer USE_NOT_ALLOWED huawei-aksk \
  --method GET --url "$HW_VERIFY/other/servers"
neg "huawei unregistered host rejected" bind_hw_signer USE_NOT_ALLOWED huawei-aksk \
  --method GET --url "http://127.0.0.1:1/kk/servers"

TC3_STATS_AFTER="$(curl -sS "$TC3_VERIFY/stats")"
TC3_VERIFIED_AFTER="$(printf '%s' "$TC3_STATS_AFTER" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verified"])')"
HW_STATS_AFTER="$(curl -sS "$HW_VERIFY/stats")"
HW_VERIFIED_AFTER="$(printf '%s' "$HW_STATS_AFTER" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verified"])')"
check "rejected tc3 requests produced no signature" "$TC3_VERIFIED_BEFORE" "$TC3_VERIFIED_AFTER"
check "rejected huawei requests produced no signature" "$HW_VERIFIED_BEFORE" "$HW_VERIFIED_AFTER"

mkdir -p "$OUT_DIR"
HOST_OS="$(sw_vers -productVersion)"
ARCH="$(uname -m)"
GO_VERSION="$(go version)"
python3 - "$WORK/env.json" "$HOST_OS" "$ARCH" "$GO_VERSION" "$TC3_VERIFY" "$HW_VERIFY" <<'PY'
import json, sys
json.dump({
    "os": "macOS " + sys.argv[2],
    "arch": sys.argv[3],
    "go": sys.argv[4],
    "tc3_upstream": sys.argv[5],
    "huawei_upstream": sys.argv[6],
    "upstream": "tests/fixtures/cloudsignverify (TC3 / SDK-HMAC-SHA256 independent recomputation, no credential persistence)",
}, open(sys.argv[1], "w"))
PY

printf '%s' "$TC3_STATS_AFTER" > "$WORK/tc3-stats.json"
printf '%s' "$HW_STATS_AFTER" > "$WORK/hw-stats.json"

python3 - "$OUT_DIR/result.json" "$WORK/env.json" "$WORK/tc3-stats.json" "$WORK/hw-stats.json" "${CHECK_RESULTS[@]}" <<'PY'
import json, sys
out_path, env_path, tc3_path, hw_path = sys.argv[1:5]
env = json.load(open(env_path))
tc3 = json.load(open(tc3_path))
hw = json.load(open(hw_path))
checks = []
for raw in sys.argv[5:]:
    parts = raw.split("|", 2)
    checks.append({"status": parts[0], "name": parts[1], "detail": parts[2] if len(parts) > 2 else ""})
failed = [c for c in checks if c["status"] != "PASS"]
out = {
    "phase": "tencent-huawei-signer",
    "protocols": [{
        "id": "tencent-tc3",
        "algorithm": "TC3-HMAC-SHA256",
        "adapter_id": "tencent-tc3/<region>/<service>",
        "methods": ["GET", "POST"],
        "canonical_uri": "/ (API 3.0 固定值；其他路径直接拒绝)",
        "signed_headers": ["content-type", "host", "x-tc-action（给出 action 时）", "content-md5（可选）"],
        "session_token_delivery": "X-TC-Token 作为请求头返回；TC3 的 Token 不参与 CanonicalHeaders（与官方 SDK 一致）。",
        "vectors": [
            "腾讯云文档 POST 示例（content-type;host）：Signature=72e494ea809ad7a8c8f7a4507b9bddcbaa8e581f516e8da2f66e2c5a96525168",
            "腾讯云文档 POST 示例（content-type;host;x-tc-action）：HashedCanonicalRequest=7019a55b…，用文档公布的 SecretSigning 复算得到文档公布的 Signature=10b1a37a…",
        ],
        "upstream": {"requests": tc3.get("requests", 0), "verified": tc3.get("verified", 0), "failed": tc3.get("failed", 0)},
    }, {
        "id": "huawei-aksk",
        "algorithm": "SDK-HMAC-SHA256",
        "adapter_id": "huawei-aksk/<region>/<service>",
        "methods": ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        "canonical_uri": "逐段 RFC3986 编码，并以 / 结尾",
        "signed_headers": ["host", "x-sdk-date", "content-type（可选）", "content-md5（可选）", "x-security-token（有会话令牌时）"],
        "session_token_delivery": "X-Security-Token 作为请求头返回并参与签名。",
        "vectors": [
            "华为云《API签名指南》VPC 查询示例：HashedCanonicalRequest=b25362e6…（文档把 SK 打码，签名值无法在无 SK 时复算）",
            "固定回归向量 GET/POST 各一组：完整 Authorization 写死，由受控校验上游独立复算",
        ],
        "upstream": {"requests": hw.get("requests", 0), "verified": hw.get("verified", 0), "failed": hw.get("failed", 0)},
    }],
    "dispatch": "POST /v1/signatures 按 Binding.AdapterID 前缀分派：aws-sigv4/、tencent-tc3/、huawei-aksk/",
    "credential": "access_key_pair：access_id/access_secret/session_token 必须同一版本完整；缺字段不补默认值。",
    "limits": {
        "single_complete_sha256_payload": True,
        "chunked_streaming_payload": False,
        "tencent_post_with_query": False,
        "real_cloud_endpoint_tested": False,
    },
    "logging": "签名材料不写入日志或审计；secret 只在本进程内使用，响应只含签名头与许可元数据。",
    "environment": env,
    "checks": checks,
    "summary": {"total": len(checks), "failed": len(failed)},
}
json.dump(out, open(out_path, "w"), indent=2, ensure_ascii=False)
print(f"checks={len(checks)} failed={len(failed)}")
PY

if python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["summary"]["failed"] == 0 else 1)' "$OUT_DIR/result.json"; then
  log "tencent/huawei signer acceptance PASSED"
else
  log "tencent/huawei signer acceptance has failures; see $OUT_DIR/result.json"
  exit 1
fi
