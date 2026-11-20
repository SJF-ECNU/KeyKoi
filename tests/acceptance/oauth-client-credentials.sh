#!/usr/bin/env bash
# OAuth2 client_credentials 与 JWT 断言（GCP 服务账号形态）网关适配验收。
#
# 全部使用运行时生成的测试凭据与受控 token 提供方（tests/fixtures/oauthtoken）；
# 不接触真实服务商 client_secret、服务账号私钥或线上 token 端点。
#
# 覆盖：basic / post 两种客户端认证、jwt-bearer 断言签名与声明校验、
# token 缓存命中与过期刷新、失败不缓存、错误分类（401/502）与密钥不泄露。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/oauth-client-credentials}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-oauth-cc.XXXXXX")"
BIN="$WORK/bin"; DATA="$WORK/data"; HOME_DIR="$WORK/home"
mkdir -p "$BIN" "$DATA" "$HOME_DIR" "$OUT_DIR"
log() { printf '%s\n' "$*" >&2; }

cleanup() {
  set +e
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  [ -n "${FIXTURE_PID:-}" ] && kill "$FIXTURE_PID" 2>/dev/null
  wait 2>/dev/null
  if [ "${KEEP_WORK:-0}" = "1" ]; then echo "work dir kept: $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

cd "$ROOT"
log "building binaries"
GO_VERSION="$(go version | awk '{print $3}')"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/oauthtoken" ./tests/fixtures/oauthtoken

export KEYKOI_DATA_DIR="$DATA" KEYKOI_SOCKET="$DATA/keykoid.sock" HOME="$HOME_DIR"
export NO_PROXY="127.0.0.1,localhost,::1" no_proxy="127.0.0.1,localhost,::1"
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

jget() { # file dotted.path
  python3 - "$1" "$2" <<'PY'
import json, sys
with open(sys.argv[1]) as fh:
    cur = json.load(fh)
for part in sys.argv[2].split("."):
    cur = cur[int(part)] if isinstance(cur, list) else cur[part]
print("" if cur is None else ("true" if cur is True else ("false" if cur is False else cur)))
PY
}

# 服务账号私钥在运行时生成；公钥交给受控提供方验证断言签名。
log "generating an RSA service-account key"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/sa-key.pem" >"$WORK/openssl.log" 2>&1
openssl rsa -in "$WORK/sa-key.pem" -pubout -out "$WORK/sa-key.pub.pem" >>"$WORK/openssl.log" 2>&1

SCOPE="chat.read"
CLIENT_EMAIL="keykoi-acceptance@example.iam.gserviceaccount.com"
log "starting controlled token provider and upstream"
"$BIN/oauthtoken" --addr 127.0.0.1:0 \
  --addr-file "$WORK/provider.addr" --client-file "$WORK/provider.json" \
  --public-key "$WORK/sa-key.pub.pem" \
  --client-email "$CLIENT_EMAIL" --scope "$SCOPE" --expires-in 65 \
  >"$WORK/provider.log" 2>&1 &
FIXTURE_PID=$!
for _ in $(seq 1 100); do
  [ -s "$WORK/provider.addr" ] && [ -s "$WORK/provider.json" ] && break
  sleep 0.1
done
[ -s "$WORK/provider.json" ] || { log "controlled token provider did not start"; exit 1; }
PROVIDER_ADDR="$(cat "$WORK/provider.addr")"
FIXTURE="http://$PROVIDER_ADDR"
TOKEN_ENDPOINT="$(jget "$WORK/provider.json" token_endpoint)"
UPSTREAM_ORIGIN="$(jget "$WORK/provider.json" upstream_origin)"
CLIENT_ID="$(jget "$WORK/provider.json" client_id)"
CLIENT_SECRET="$(jget "$WORK/provider.json" client_secret)"
# post 与 basic 使用同一组客户端凭据，差异只在认证方式（表单体 vs Basic 头）。
POST_CLIENT_ID="$CLIENT_ID"
POST_CLIENT_SECRET="$CLIENT_SECRET"
BAD_CLIENT_SECRET="keykoi-wrong-secret-$(openssl rand -hex 6)"
log "fixture=$FIXTURE token_endpoint=$TOKEN_ENDPOINT"

log "starting keykoid (encrypted vault)"
KEYKOI_OAUTH_ALLOW_LOOPBACK_HTTP=1 "$BIN/keykoid" --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for _ in $(seq 1 100); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
GW="$("$BIN/keykoi" --json status | python3 -c 'import json,sys;print(json.load(sys.stdin)["gateway"])')"
[ -n "$GW" ] || { log "daemon did not report a gateway address"; exit 1; }
printf 'oauth-client-credentials-password\n' | "$BIN/keykoi" init --password-stdin >/dev/null
PRINCIPAL="principal_local_$(id -u)"
log "gateway=$GW"

add_credential() { # label field... ; prints credential id
  local label="$1"; shift
  local args=()
  for kv in "$@"; do args+=(--field "$kv"); done
  "$BIN/keykoi" --json credential add --kind oauth --label "$label" "${args[@]}" | tr -d '\n'
}

add_proxy_binding() { # id credential route scheme
  "$BIN/keykoi" --json binding add --id "$1" --credential "$2" --origin "$UPSTREAM_ORIGIN" \
    --route "$3" --scheme "$4" --paths /api >/dev/null
  "$BIN/keykoi" --json grant add --principal "$PRINCIPAL" --binding "$1" --mode proxy --auth permanent --max-lease-seconds 600 >/dev/null
}

log "seeding oauth credentials and bindings"
CRED_CC="$(add_credential "client credentials (basic)" \
  "token_endpoint=$TOKEN_ENDPOINT" "client_id=$CLIENT_ID" "client_secret=$CLIENT_SECRET" "scope=$SCOPE")"
CRED_POST="$(add_credential "client credentials (post)" \
  "token_endpoint=$TOKEN_ENDPOINT" "client_id=$POST_CLIENT_ID" "client_secret=$POST_CLIENT_SECRET" \
  "scope=$SCOPE" "client_auth=post")"
CRED_JWT="$(add_credential "service account jwt bearer" \
  "client_email=$CLIENT_EMAIL" "private_key=$(cat "$WORK/sa-key.pem")" \
  "token_uri=$TOKEN_ENDPOINT" "scope=$SCOPE")"
CRED_JWT_SCOPE="$(add_credential "service account wrong scope" \
  "client_email=$CLIENT_EMAIL" "private_key=$(cat "$WORK/sa-key.pem")" \
  "token_uri=$TOKEN_ENDPOINT" "scope=other.scope")"
CRED_BAD="$(add_credential "client credentials (wrong secret)" \
  "token_endpoint=$TOKEN_ENDPOINT" "client_id=$CLIENT_ID" "client_secret=$BAD_CLIENT_SECRET" "scope=$SCOPE")"
CRED_MISSING="$(add_credential "client credentials (missing endpoint)" \
  "client_id=$CLIENT_ID" "client_secret=$CLIENT_SECRET")"

add_proxy_binding bind_cc "$CRED_CC" cc oauth_client_credentials
add_proxy_binding bind_post "$CRED_POST" ccpost oauth_client_credentials
add_proxy_binding bind_jwt "$CRED_JWT" jwt oauth_jwt_bearer
add_proxy_binding bind_jwt_scope "$CRED_JWT_SCOPE" jwtscope oauth_jwt_bearer
add_proxy_binding bind_bad "$CRED_BAD" cc-bad oauth_client_credentials
add_proxy_binding bind_missing "$CRED_MISSING" cc-missing oauth_client_credentials

TOKEN="$(python3 - "$DATA" <<'PY'
import http.client, socket, json, os, sys
sock = os.path.join(sys.argv[1], "keykoid.sock")
class U(http.client.HTTPConnection):
    def __init__(self): super().__init__("keykoi.local")
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.sock.connect(sock)
c = U(); c.request("POST", "/v1/sessions", json.dumps({"purpose": "oauth-client-credentials"}), {"Content-Type": "application/json"})
print(json.loads(c.getresponse().read())["token"])
PY
)"

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

statv() { # name -> value from the controlled provider
  curl -sS "$FIXTURE/stats" | python3 -c 'import json,sys;print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}
gateway_get() { # route -> writes body to $WORK/body.json, prints HTTP status
  curl -sS -o "$WORK/body.json" -w '%{http_code}' \
    -H "X-KeyKoi-Session: $TOKEN" "http://$GW/gateway/$1/api/echo"
}
body_error_code() {
  python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("error",{}).get("code",""))' "$WORK/body.json"
}
body_error_message() {
  python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("error",{}).get("message",""))' "$WORK/body.json"
}

log "1) client_credentials（HTTP Basic 客户端认证）"
CODE1="$(gateway_get cc)"
check "client_credentials request through the gateway returns 200" "200" "$CODE1"
check "upstream accepted the fixture-issued Bearer token" "true" "$(jget "$WORK/body.json" ok)"
CODE2="$(gateway_get cc)"
check "second client_credentials request returns 200" "200" "$CODE2"
check "two gateway requests triggered exactly one token exchange" "1" "$(statv token_requests)"
check "token endpoint saw HTTP Basic client authentication" "1" "$(statv client_auth_basic)"
check "upstream received the issued Bearer on both requests" "2" "$(statv upstream_matched)"
check "the intermediary session token never reached the upstream" "0" "$(statv session_tokens_seen)"

log "2) client_credentials（client_secret_post）"
CODE_POST="$(gateway_get ccpost)"
check "post-mode client_credentials request returns 200" "200" "$CODE_POST"
check "token endpoint saw client credentials in the form body" "1" "$(statv client_auth_post)"

log "3) 服务账号 JWT 断言（jwt-bearer）"
CODE_JWT="$(gateway_get jwt)"
check "jwt_bearer request through the gateway returns 200" "200" "$CODE_JWT"
check "fixture verified the RS256 assertion signature and claims" "1" "$(statv jwt_verified)"
check "no assertion was rejected for a bad signature or claim" "0" "$(( $(statv jwt_bad_signature) + $(statv jwt_bad_claims) ))"
CODE_SCOPE="$(gateway_get jwtscope)"
check "assertion with a foreign scope is rejected by the token endpoint" "401" "$CODE_SCOPE"
check "scope mismatch surfaces as UPSTREAM_AUTH_FAILED" "UPSTREAM_AUTH_FAILED" "$(body_error_code)"
check "fixture rejected the assertion on its claims" "1" "$(statv jwt_bad_claims)"

log "4) 错误 client_secret：401 语义、失败不缓存、无泄露"
REJECTED_BEFORE="$(statv rejected_client)"
CODE_BAD1="$(gateway_get cc-bad)"
BAD1_BODY="$(cat "$WORK/body.json")"
CODE_BAD2="$(gateway_get cc-bad)"
check "wrong client_secret returns 401" "401" "$CODE_BAD1"
check "wrong client_secret surfaces as UPSTREAM_AUTH_FAILED" "UPSTREAM_AUTH_FAILED" "$(body_error_code)"
check "wrong client_secret is rejected on every attempt (failures are not cached)" "2" "$(( $(statv rejected_client) - REJECTED_BEFORE ))"
check "gateway error body does not contain the client_secret" "0" "$(printf '%s' "$BAD1_BODY" | grep -cF "$BAD_CLIENT_SECRET" || true)"

log "5) 缺字段：CREDENTIAL_UNAVAILABLE"
CODE_MISSING="$(gateway_get cc-missing)"
check "missing token_endpoint returns 503" "503" "$CODE_MISSING"
check "missing token_endpoint surfaces as CREDENTIAL_UNAVAILABLE" "CREDENTIAL_UNAVAILABLE" "$(body_error_code)"

log "6) 缓存过期后重新换取"
sleep 6
TOKENS_BEFORE="$(statv token_requests)"
CODE_REFRESH="$(gateway_get cc)"
check "request after the cache window still returns 200" "200" "$CODE_REFRESH"
check "expired cached token is exchanged again exactly once" "1" "$(( $(statv token_requests) - TOKENS_BEFORE ))"

log "7) token 端点 5xx：UPSTREAM_UNAVAILABLE"
curl -sS -X POST -d '{"fail_status":503,"fail_code":"temporarily_unavailable"}' "$FIXTURE/control" >/dev/null
CRED_5XX="$(add_credential "client credentials (upstream 5xx)" \
  "token_endpoint=$TOKEN_ENDPOINT" "client_id=$CLIENT_ID" "client_secret=$CLIENT_SECRET" "scope=$SCOPE")"
add_proxy_binding bind_5xx "$CRED_5XX" cc-5xx oauth_client_credentials
CODE_5XX="$(gateway_get cc-5xx)"
check "token endpoint 5xx returns 502" "502" "$CODE_5XX"
check "token endpoint 5xx surfaces as UPSTREAM_UNAVAILABLE" "UPSTREAM_UNAVAILABLE" "$(body_error_code)"
curl -sS -X POST -d '{"fail_status":0,"fail_code":""}' "$FIXTURE/control" >/dev/null

log "8) 秘密不进入日志、错误与产物"
curl -sS "$FIXTURE/tokens" >"$WORK/issued.json"
LEAKS="$(python3 - "$WORK/issued.json" "$WORK/keykoid.log" "$CLIENT_SECRET" "$POST_CLIENT_SECRET" "$BAD_CLIENT_SECRET" <<'PY'
import json, sys
tokens_file, log_file, *secrets = sys.argv[1:]
log = open(log_file, encoding="utf-8", errors="replace").read()
issued = json.load(open(tokens_file))["tokens"]
leaks = 0
for value in list(secrets) + list(issued):
    if value and value in log:
        leaks += 1
print(leaks)
PY
)"
check "keykoid log contains no access token, client_secret or private key" "0" "$LEAKS"
check "keykoid log contains no signed JWT assertion" "0" "$(grep -c 'eyJ' "$WORK/keykoid.log" || true)"
check "fixture never saw an intermediary session token" "0" "$(grep -c 'kks_' "$WORK/provider.log" || true)"

ENVIRONMENT="$(uname -sm) / $GO_VERSION / openssl $(openssl version | awk '{print $2}')"
python3 - "$OUT_DIR/result.json" "$ENVIRONMENT" "$GW" "${CHECK_RESULTS[@]}" <<'PY'
import json, sys
out = {
  "phase": "oauth-client-credentials",
  "environment": {
    "host": sys.argv[2],
    "gateway": sys.argv[3],
    "token_provider": "controlled fixture (tests/fixtures/oauthtoken) on loopback",
    "upstream": "same fixture; only accepts its own Bearer tokens",
    "credentials": "generated at runtime (client_secret, RSA service-account key)",
    "note": "未接触真实服务商端点或密钥；GCP 真实 token_uri 未测。",
  },
  "checks": [],
}
for raw in sys.argv[4:]:
    status, name, detail = raw.split("|", 2)
    out["checks"].append({"status": status, "name": name, "detail": detail})
out["summary"] = {"total": len(out["checks"]), "failed": sum(1 for c in out["checks"] if c["status"] != "PASS")}
with open(sys.argv[1], "w") as fh:
    json.dump(out, fh, indent=2, ensure_ascii=False)
print(f"checks={out['summary']['total']} failed={out['summary']['failed']}")
PY

grep -q '"failed": 0' "$OUT_DIR/result.json" || { log "oauth client credentials acceptance FAILED"; exit 1; }
log "oauth client credentials acceptance PASSED"
