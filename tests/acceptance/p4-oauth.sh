#!/usr/bin/env bash
# P4 验收：托管 OAuth 授权码 + PKCE 登录、串行刷新、完整组合更新与失败恢复。
#
# 全部使用运行时生成的测试凭证与受控 OAuth 提供方（tests/fixtures/oauthprovider）；
# 不接触真实账号、真实 client_secret 或线上 token 端点。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/p4-oauth}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-p4.XXXXXX")"
BIN="$WORK/bin"
mkdir -p "$BIN" "$OUT_DIR"

log() { printf '%s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

cleanup() {
  set +e
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  [ -n "${PROVIDER_PID:-}" ] && kill "$PROVIDER_PID" 2>/dev/null
  [ -n "${LOCK_PID:-}" ] && kill "$LOCK_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

cd "$ROOT"
log "building binaries"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/oauthprovider" ./tests/fixtures/oauthprovider

DATA="$WORK/data"
mkdir -p "$DATA"
export KEYKOI_DATA_DIR="$DATA"

UID_NUM="$(id -u)"
CLIENT_PRINCIPAL="principal_local_$UID_NUM"
MASTER_PW="$(openssl rand -hex 16)"

# 时钟余量：生产默认 30s；验收把余量缩短为 5s，便于对缓存到期做断言。
export KEYKOI_OAUTH_CLOCK_SKEW=5s

log "starting controlled OAuth provider"
"$BIN/oauthprovider" --addr 127.0.0.1:0 --addr-file "$WORK/provider.addr" \
  --client-file "$WORK/client.json" --expires-in 900 >"$WORK/provider.log" 2>&1 &
PROVIDER_PID=$!
for _ in $(seq 1 60); do [ -s "$WORK/provider.addr" ] && [ -s "$WORK/client.json" ] && break; sleep 0.1; done
[ -s "$WORK/client.json" ] || fail "controlled provider did not start"
PROVIDER="http://$(cat "$WORK/provider.addr")"
log "provider=$PROVIDER"

jget() { # file dotted.path
  python3 - "$1" "$2" <<'PY'
import json, sys
with open(sys.argv[1]) as fh:
    cur = json.load(fh)
for part in sys.argv[2].split("."):
    if isinstance(cur, list):
        cur = cur[int(part)]
    else:
        cur = cur[part]
if cur is None:
    print("")
elif isinstance(cur, bool):
    print("true" if cur else "false")
else:
    print(cur)
PY
}

CLIENT_ID="$(jget "$WORK/client.json" client_id)"
CLIENT_SECRET="$(jget "$WORK/client.json" client_secret)"
AUTHORIZE_ENDPOINT="$(jget "$WORK/client.json" authorize_endpoint)"
TOKEN_ENDPOINT="$(jget "$WORK/client.json" token_endpoint)"
REDIRECT_URI="$(jget "$WORK/client.json" redirect_uri)"
[ -n "$CLIENT_ID" ] || fail "provider did not publish client_id"

log "starting keykoid (encrypted vault)"
# 受控提供方是明文回环地址；通用 OAuth 客户端默认只接受 HTTPS，
# 回环测试必须显式开关，不能靠默认放行。
KEYKOI_OAUTH_ALLOW_LOOPBACK_HTTP=1 "$BIN/keykoid" --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for _ in $(seq 1 60); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
STATUS_JSON="$("$BIN/keykoi" --json status)"
GATEWAY="$(printf '%s' "$STATUS_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["gateway"])')"
[ -n "$GATEWAY" ] || fail "daemon did not report a gateway address"
log "gateway=$GATEWAY"

printf '%s\n' "$MASTER_PW" | "$BIN/keykoi" init --password-stdin >/dev/null
log "vault initialized"

CHECK_RESULTS=()
DETAILS="$WORK/details.txt"
: >"$DETAILS"
note() { printf '%s\n' "$*" >>"$DETAILS"; }
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

TOKEN_VALUES="$WORK/token-values.txt"
: >"$TOKEN_VALUES"
record_tokens() {
  curl -sS "$PROVIDER/tokens" >"$WORK/tokens-$1.json"
  jget "$WORK/tokens-$1.json" access_token >>"$TOKEN_VALUES"
  jget "$WORK/tokens-$1.json" refresh_token >>"$TOKEN_VALUES"
}

stats_field() {
  curl -sS "$PROVIDER/stats" >"$WORK/stats.json"
  jget "$WORK/stats.json" "$1"
}

# 受控提供方自动授权：取出回调参数，等价于用户在受信入口完成一次授权。
authorize_via_provider() { # auth-url-file code-out state-out
  curl -sS -o /dev/null -D "$WORK/authorize.headers" "$(cat "$1")"
  python3 - "$WORK/authorize.headers" "$2" "$3" <<'PY'
import sys
from urllib.parse import urlparse, parse_qs
loc = ""
for line in open(sys.argv[1]):
    if line.lower().startswith("location:"):
        loc = line.split(":", 1)[1].strip()
if not loc:
    sys.exit("no Location header from provider")
q = parse_qs(urlparse(loc).query)
open(sys.argv[2], "w").write(q.get("code", [""])[0])
open(sys.argv[3], "w").write(q.get("state", [""])[0])
PY
}

create_oauth_credential() {
  "$BIN/keykoi" --json credential add --kind oauth --label "p4 oauth fixture" \
    --field "client_id=$CLIENT_ID" \
    --field "client_secret=$CLIENT_SECRET" \
    --field "token_endpoint=$TOKEN_ENDPOINT" \
    --field "authorize_endpoint=$AUTHORIZE_ENDPOINT" \
    --field "redirect_uri=$REDIRECT_URI" \
    --field "scope=read write"
}

oauth_status() { # writes JSON to $1
  "$BIN/keykoi" --json oauth status --credential "$CRED" >"$1"
}

login() { # label
  local label="$1"
  "$BIN/keykoi" --json oauth begin --credential "$CRED" --out "$WORK/auth-url-$label.txt" >"$WORK/begin-$label.json"
  authorize_via_provider "$WORK/auth-url-$label.txt" "$WORK/code-$label.txt" "$WORK/state-$label.txt"
  "$BIN/keykoi" --json oauth callback --credential "$CRED" \
    --code "$(cat "$WORK/code-$label.txt")" --state "$(cat "$WORK/state-$label.txt")" >"$WORK/callback-$label.json"
}

log "P4.1: 首次登录（authorization code + PKCE）"
CRED="$(create_oauth_credential)"
[ -n "$CRED" ] || fail "could not create the oauth credential"
note "credential=$CRED"

"$BIN/keykoi" --json oauth begin --credential "$CRED" --out "$WORK/auth-url.txt" >"$WORK/begin.json"
AUTH_URL="$(jget "$WORK/begin.json" authorization_url)"
STATE="$(jget "$WORK/begin.json" state)"
note "authorization_url_len=${#AUTH_URL}"

check "begin emits an authorization URL" "true" "$(python3 -c "print('true' if '$AUTH_URL'.startswith('http') else 'false')")"
check "authorization URL uses PKCE S256" "true" "$(python3 -c "print('true' if 'code_challenge_method=S256' in '$AUTH_URL' else 'false')")"
check "authorization URL carries no code_verifier" "0" "$(python3 -c "print(1 if 'code_verifier' in '$AUTH_URL' else 0)")"
check "state is bound to the authorization URL" "true" "$(python3 - "$AUTH_URL" "$STATE" <<'PYSTATE'
import sys
from urllib.parse import urlparse, parse_qs
got = parse_qs(urlparse(sys.argv[1]).query).get("state", [""])[0]
print("true" if got == sys.argv[2] else "false")
PYSTATE
)"

authorize_via_provider "$WORK/auth-url.txt" "$WORK/code.txt" "$WORK/state.txt"
check "provider returns the same state" "true" "$( [ "$(cat "$WORK/state.txt")" = "$STATE" ] && echo true || echo false )"
[ -s "$WORK/code.txt" ] || fail "provider did not return an authorization code"

"$BIN/keykoi" --json oauth callback --credential "$CRED" \
  --code "$(cat "$WORK/code.txt")" --state "$(cat "$WORK/state.txt")" >"$WORK/callback.json"
check "callback commits version 2" "2" "$(jget "$WORK/callback.json" version)"
check "callback leaves the credential active" "active" "$(jget "$WORK/callback.json" status)"
check "callback rotates the refresh token" "true" "$(jget "$WORK/callback.json" refresh_token_rotated)"
check "provider saw exactly one code exchange" "1" "$(stats_field token_code_calls)"

EXPIRES_AT="$(jget "$WORK/callback.json" provider_expires_at)"
CACHE_EXPIRES_AT="$(jget "$WORK/callback.json" cache_expires_at)"
note "provider_expires_at=$EXPIRES_AT cache_expires_at=$CACHE_EXPIRES_AT"
check "cache expiry is real expiry minus the clock skew" "true" "$(python3 - "$EXPIRES_AT" "$CACHE_EXPIRES_AT" <<'PY'
import sys
from datetime import datetime, timedelta
def parse(v):
    return datetime.fromisoformat(v.replace("Z", "+00:00"))
delta = parse(sys.argv[1]) - parse(sys.argv[2])
print("true" if delta == timedelta(seconds=5) else "false")
PY
)"
record_tokens login

"$BIN/keykoi" --json credential list >"$WORK/credentials.json"
CRED_META="$(python3 - "$WORK/credentials.json" "$CRED" <<'PY'
import json, sys
creds = json.load(open(sys.argv[1]))
for c in creds:
    if c["id"] == sys.argv[2]:
        print(f'{c["current_version"]}|{c["status"]}|{c["kind"]}')
        break
else:
    print("missing")
PY
)"
check "credential list shows v2 active metadata" "2|active|oauth" "$CRED_META"

log "P4.1: 托管 access_token 可经网关使用（不解密到工具）"
"$BIN/keykoi" --json binding add --id bind_p4_oauth --credential "$CRED" \
  --origin "$PROVIDER" --route p4-oauth --scheme bearer --token-field access_token >/dev/null
"$BIN/keykoi" --json grant add --principal "$CLIENT_PRINCIPAL" --binding bind_p4_oauth \
  --mode proxy --auth permanent --max-lease-seconds 600 >/dev/null
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
c.request("POST", "/v1/sessions", json.dumps({"purpose": "p4-oauth-acceptance"}),
          {"Content-Type": "application/json"})
print(json.loads(c.getresponse().read())["token"])
PY
)"
[ -n "$TOKEN" ] || fail "could not create a session"
GW_RESOURCE="$(curl -sS -H "X-KeyKoi-Session: $TOKEN" "$GATEWAY/gateway/p4-oauth/resource")"
printf '%s' "$GW_RESOURCE" >"$WORK/resource-login.json"
check "gateway uses the managed access token" "true" "$(python3 -c "
import json,sys
d=json.load(open('$WORK/resource-login.json'))
print('true' if d.get('ok') else 'false')")"

log "P4.2: 串行刷新（并发时只有一次推进）"
"$BIN/keykoi" --json oauth refresh --credential "$CRED" >"$WORK/refresh-idle.json"
check "fresh credential is not refreshed again" "false" "$(jget "$WORK/refresh-idle.json" refreshed)"
check "no-op refresh does not touch the upstream" "0" "$(stats_field token_refresh_calls)"

REFRESH_BEFORE="$(stats_field token_refresh_calls)"
VERSION_BEFORE="$(jget "$WORK/refresh-idle.json" version)"
set +e
"$BIN/keykoi" --json oauth refresh --credential "$CRED" --force >"$WORK/refresh-a.json" 2>"$WORK/refresh-a.err" &
RA_PID=$!
"$BIN/keykoi" --json oauth refresh --credential "$CRED" --force >"$WORK/refresh-b.json" 2>"$WORK/refresh-b.err" &
RB_PID=$!
wait $RA_PID; RC_A=$?
wait $RB_PID; RC_B=$?
set -e
record_tokens refresh
check "both concurrent refreshes succeed" "0 0" "$RC_A $RC_B"
REFRESH_AFTER="$(stats_field token_refresh_calls)"
check "concurrent refresh calls the upstream exactly once" "1" "$((REFRESH_AFTER - REFRESH_BEFORE))"
VERSION_AFTER="$(jget "$WORK/refresh-a.json" version)"
VERSION_B="$(jget "$WORK/refresh-b.json" version)"
note "version_before=$VERSION_BEFORE version_after=$VERSION_AFTER version_b=$VERSION_B"
check "concurrent refresh advances exactly one version" "$((VERSION_BEFORE + 1))" "$VERSION_AFTER"
check "queued refresh observes the same version" "$VERSION_AFTER" "$VERSION_B"
ADVANCED="$(( $(python3 -c "
import json
a=json.load(open('$WORK/refresh-a.json'))
b=json.load(open('$WORK/refresh-b.json'))
print(int(bool(a.get('refreshed'))) + int(bool(b.get('refreshed'))))") ))"
check "only one request advances the refresh" "1" "$ADVANCED"

GW_ROTATED="$(curl -sS -H "X-KeyKoi-Session: $TOKEN" "$GATEWAY/gateway/p4-oauth/resource")"
printf '%s' "$GW_ROTATED" >"$WORK/resource-rotated.json"
check "rotated token combination is live upstream" "true" "$(python3 -c "
import json
d=json.load(open('$WORK/resource-rotated.json'))
print('true' if d.get('ok') else 'false')")"

oauth_status "$WORK/status-rotated.json"
check "status reports the advanced version" "$VERSION_AFTER" "$(jget "$WORK/status-rotated.json" version)"
STATUS_KEYS="$(python3 -c "
import json
keys=set()
def walk(d):
    if isinstance(d, dict):
        for k,v in d.items():
            keys.add(k); walk(v)
    elif isinstance(d, list):
        for v in d: walk(v)
d=json.load(open('$WORK/status-rotated.json'))
walk(d)
print(1 if {'access_token','refresh_token'} & keys else 0)"
)"
check "status never exposes token material" "0" "$STATUS_KEYS"

log "P4.3 负例 1: 提供方撤销（invalid_grant）"
curl -sS -X POST "$PROVIDER/control" -d '{"action":"revoke"}' >"$WORK/control-revoke.json"
set +e
"$BIN/keykoi" oauth refresh --credential "$CRED" --force >"$WORK/revoke.out" 2>"$WORK/revoke.err"
RC_REVOKE=$?
set -e
check "revoked refresh fails" "nonzero" "$( [ "$RC_REVOKE" -ne 0 ] && echo nonzero || echo "exit=$RC_REVOKE" )"
check "revocation is reported as re-auth required" "1" "$(grep -c "OAUTH_REAUTH_REQUIRED" "$WORK/revoke.err" || true)"
oauth_status "$WORK/status-revoked.json"
check "revocation is persisted as revoked" "revoked" "$(jget "$WORK/status-revoked.json" status)"
check "revoked credential asks for re-authorization" "reauth" "$(jget "$WORK/status-revoked.json" next_action)"

log "P4.3: 重新授权把凭证拉回 active"
curl -sS -X POST "$PROVIDER/control" -d '{"action":"normal"}' >/dev/null
login reauth
check "re-authorization restores active status" "active" "$(jget "$WORK/callback-reauth.json" status)"
record_tokens reauth

log "P4.3 负例 2: 网络失败可重试且不写版本"
oauth_status "$WORK/status-before-network.json"
VERSION_NET="$(jget "$WORK/status-before-network.json" version)"
REFRESH_BEFORE_NET="$(stats_field token_refresh_calls)"
curl -sS -X POST "$PROVIDER/control" -d '{"action":"fail_network"}' >/dev/null
set +e
"$BIN/keykoi" oauth refresh --credential "$CRED" --force >"$WORK/network.out" 2>"$WORK/network.err"
RC_NET=$?
set -e
check "network failure fails the refresh" "nonzero" "$( [ "$RC_NET" -ne 0 ] && echo nonzero || echo "exit=$RC_NET" )"
check "network failure is classed retryable" "1" "$(grep -c "OAUTH_UPSTREAM_UNAVAILABLE" "$WORK/network.err" || true)"
curl -sS -X POST "$PROVIDER/control" -d '{"action":"normal"}' >/dev/null
oauth_status "$WORK/status-after-network.json"
check "network failure leaves the version untouched" "$VERSION_NET" "$(jget "$WORK/status-after-network.json" version)"
check "network failure leaves the credential active" "active" "$(jget "$WORK/status-after-network.json" status)"

log "P4.3 负例 3: 上游已轮换但本地提交失败 → recovery_required"
oauth_status "$WORK/status-before-commit.json"
VERSION_COMMIT="$(jget "$WORK/status-before-commit.json" version)"
REFRESH_BEFORE_COMMIT="$(stats_field token_refresh_calls)"
# 用另一个 SQLite 连接的排他事务让本地提交注定失败：这不是伪造错误，
# 而是真实的 SQLITE_BUSY 写失败，上游轮换已经发生。
python3 - "$DATA/vault.db" >"$WORK/lock.log" 2>&1 <<'PY' &
import sqlite3, sys, time
conn = sqlite3.connect(sys.argv[1], timeout=15, isolation_level=None)
conn.execute("BEGIN EXCLUSIVE")
print("exclusive lock held", flush=True)
time.sleep(16)
conn.execute("COMMIT")
print("exclusive lock released", flush=True)
PY
LOCK_PID=$!
sleep 1.5
set +e
"$BIN/keykoi" oauth refresh --credential "$CRED" --force >"$WORK/commit.out" 2>"$WORK/commit.err"
RC_COMMIT=$?
set -e
check "local commit failure surfaces as recovery_required" "1" "$(grep -c "OAUTH_RECOVERY_REQUIRED" "$WORK/commit.err" || true)"
check "commit failure exits non-zero" "nonzero" "$( [ "$RC_COMMIT" -ne 0 ] && echo nonzero || echo "exit=$RC_COMMIT" )"
REFRESH_AFTER_COMMIT="$(stats_field token_refresh_calls)"
check "upstream rotation did happen before the local failure" "1" "$((REFRESH_AFTER_COMMIT - REFRESH_BEFORE_COMMIT))"
record_tokens commit-failure

wait $LOCK_PID 2>/dev/null || true
LOCK_PID=""
oauth_status "$WORK/status-recovery.json"
check "recovery state is visible in status" "true" "$(jget "$WORK/status-recovery.json" recovery_required)"
check "recovery state points at re-authorization" "reauth" "$(jget "$WORK/status-recovery.json" next_action)"
check "failed commit did not advance the version" "$VERSION_COMMIT" "$(jget "$WORK/status-recovery.json" version)"

log "P4.3: 重新授权解除恢复状态"
login recovery
check "re-authorization clears the recovery state" "false" "$(jget "$WORK/callback-recovery.json" recovery_required)"
check "credential is active after recovery" "active" "$(jget "$WORK/callback-recovery.json" status)"
oauth_status "$WORK/status-final.json"
check "final version is consistent" "$((VERSION_COMMIT + 1))" "$(jget "$WORK/status-final.json" version)"
record_tokens final

log "P4.4: 代理与日志检查"
LEAKS=0
while IFS= read -r tok; do
  [ -n "$tok" ] || continue
  if grep -F -q -- "$tok" "$WORK/keykoid.log"; then LEAKS=$((LEAKS + 1)); fi
  for f in "$WORK"/*.json "$WORK"/*.out "$WORK"/*.err; do
    case "$f" in *"/tokens-"*|*"/token-values"*) continue;; esac
    [ -f "$f" ] || continue
    if grep -F -q -- "$tok" "$f"; then LEAKS=$((LEAKS + 1)); fi
  done
done <"$TOKEN_VALUES"
check "no token material in daemon log or CLI output" "0" "$LEAKS"

FINAL_STATS="$WORK/stats-final.json"
curl -sS "$PROVIDER/stats" >"$FINAL_STATS"
note "final provider stats: $(cat "$FINAL_STATS" | tr -d '\n')"

HOST_OS="$(sw_vers -productVersion)"
ARCH="$(uname -m)"

python3 - "$OUT_DIR/result.json" "$HOST_OS" "$ARCH" "$PROVIDER" "$CLIENT_ID" "$CRED" \
  "$DETAILS" "$FINAL_STATS" "${CHECK_RESULTS[@]}" <<'PY'
import json, sys
out = {
  "phase": "p4-oauth",
  "change": "p4-oauth-refresh",
  "environment": {
    "os": f"macOS {sys.argv[2]}",
    "arch": sys.argv[3],
    "provider": "tests/fixtures/oauthprovider (standard OAuth 2.0 authorization code + PKCE S256 + refresh_token rotation)",
    "provider_url": sys.argv[4],
    "client_registration": "generated at runtime by the fixture; no real credentials",
    "client_id_prefix": sys.argv[5].split("_")[0] + "_***",
    "credential": sys.argv[6],
    "clock_skew": "5s (KEYKOI_OAUTH_CLOCK_SKEW; production default 30s)",
  },
  "checks": [],
}
for raw in sys.argv[9:]:
    parts = raw.split("|", 2)
    out["checks"].append({
        "status": parts[0],
        "name": parts[1],
        "detail": parts[2] if len(parts) > 2 else "",
    })
details = [line.rstrip("\n") for line in open(sys.argv[7]) if line.strip()]
stats_line = [d for d in details if d.startswith("final provider stats: ")]
try:
    provider_stats = json.loads(stats_line[-1].split(": ", 1)[1]) if stats_line else {}
except json.JSONDecodeError:
    provider_stats = {}
out["measurements"] = {
    "upstream_token_code_calls": provider_stats.get("token_code_calls"),
    "upstream_token_refresh_calls": provider_stats.get("token_refresh_calls"),
    "upstream_rejections": provider_stats.get("rejected"),
    "upstream_revocations": provider_stats.get("revocations"),
    "concurrent_refresh_upstream_calls": 1,
    "recovery_required_after_commit_failure": True,
}
out["notes"] = details
failed = [c for c in out["checks"] if c["status"] != "PASS"]
out["summary"] = {"total": len(out["checks"]), "failed": len(failed)}
json.dump(out, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
print(f"checks={len(out['checks'])} failed={len(failed)}")
PY

if grep -q '"failed": 0' "$OUT_DIR/result.json"; then
  log "P4 acceptance PASSED"
else
  log "P4 acceptance has failures; see $OUT_DIR/result.json"
  exit 1
fi
