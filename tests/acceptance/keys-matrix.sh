#!/usr/bin/env bash
# 业务凭证矩阵：Bearer、自定义 Key 头、Basic、Git helper 和代理启动器。
# 所有请求均使用本地受控上游。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/keys-matrix}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-keys.XXXXXX")"
BIN="$WORK/bin"; DATA="$WORK/data"; HOME_DIR="$WORK/home"
mkdir -p "$BIN" "$DATA" "$HOME_DIR" "$OUT_DIR"
log() { printf '%s\n' "$*" >&2; }

cleanup() {
  set +e
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  for pid in ${UP_PIDS:-}; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  if [ "${KEEP_WORK:-0}" = "1" ]; then echo "work dir kept: $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

cd "$ROOT"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/mockupstream" ./tests/fixtures/mockupstream

export KEYKOI_DATA_DIR="$DATA" KEYKOI_SOCKET="$DATA/keykoid.sock" HOME="$HOME_DIR"
export NO_PROXY="127.0.0.1,localhost,::1" no_proxy="127.0.0.1,localhost,::1"
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
BEARER_KEY="billing-$(openssl rand -hex 10)"
HEADER_KEY="inventory-$(openssl rand -hex 10)"
BASIC_USER="elastic"
BASIC_PASS="$(openssl rand -hex 10)"
GIT_USER="x-access-token"
GIT_PASS="ghp_keykoi_$(openssl rand -hex 10)"

UP_BEARER=$(port); UP_HEADER=$(port); UP_BASIC=$(port)
UP_PIDS=""
"$BIN/mockupstream" --addr "127.0.0.1:$UP_BEARER" --expect "Bearer $BEARER_KEY" >"$WORK/up-bearer.log" 2>&1 & UP_PIDS="$UP_PIDS $!"
"$BIN/mockupstream" --addr "127.0.0.1:$UP_HEADER" --expect-header "x-inventory-key=$HEADER_KEY" >"$WORK/up-header.log" 2>&1 & UP_PIDS="$UP_PIDS $!"
"$BIN/mockupstream" --addr "127.0.0.1:$UP_BASIC" --expect "Basic $(printf '%s:%s' "$BASIC_USER" "$BASIC_PASS" | base64)" >"$WORK/up-basic.log" 2>&1 & UP_PIDS="$UP_PIDS $!"
for i in $(seq 1 80); do
  ok=1
  for p in "$UP_BEARER" "$UP_HEADER" "$UP_BASIC"; do curl -fsS "http://127.0.0.1:$p/stats" >/dev/null 2>&1 || ok=0; done
  [ "$ok" = "1" ] && break; sleep 0.1
done

log "keykoid + seed bindings for each key shape"
"$BIN/keykoid" --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for i in $(seq 1 80); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
printf 'keys-matrix-password\n' | "$BIN/keykoi" init --password-stdin >/dev/null
GW="$("$BIN/keykoi" --json status | python3 -c 'import json,sys;print(json.load(sys.stdin)["gateway"])')"
PRINCIPAL="principal_local_$(id -u)"

seed() { # kind label binding route origin scheme header field...
  local kind="$1" label="$2" id="$3" route="$4" origin="$5" scheme="$6" header="$7"; shift 7
  local args=()
  for kv in "$@"; do args+=(--field "$kv"); done
  local cred
  cred="$("$BIN/keykoi" --json credential add --kind "$kind" --label "$label" "${args[@]}" | tr -d '\n')"
  if [ -n "$header" ]; then
    "$BIN/keykoi" --json binding add --id "$id" --credential "$cred" --origin "$origin" --route "$route" --scheme "$scheme" --header "$header" >/dev/null
  else
    "$BIN/keykoi" --json binding add --id "$id" --credential "$cred" --origin "$origin" --route "$route" --scheme "$scheme" >/dev/null
  fi
  "$BIN/keykoi" --json grant add --principal "$PRINCIPAL" --binding "$id" --mode proxy --auth permanent --max-lease-seconds 300 >/dev/null
  echo "$cred"
}

seed api_key     "billing key"        bind_bearer    billing   "http://127.0.0.1:$UP_BEARER"    bearer  ""               "token=$BEARER_KEY"    >/dev/null
seed api_key     "inventory key"     bind_header inventory "http://127.0.0.1:$UP_HEADER"    api_key x-inventory-key        "token=$HEADER_KEY"    >/dev/null
seed database    "basic credential"  bind_basic     basic     "http://127.0.0.1:$UP_BASIC"  basic   ""               "username=$BASIC_USER" "password=$BASIC_PASS" >/dev/null
seed api_key     "git token"         bind_git       git       "http://127.0.0.1:1"          basic   ""               "username=$GIT_USER" "password=$GIT_PASS" >/dev/null
"$BIN/keykoi" --json grant add --principal "$PRINCIPAL" --binding bind_git --mode runtime_delivery --auth permanent --max-lease-seconds 300 >/dev/null

TOKEN="$(python3 - "$DATA" <<'PY'
import http.client, socket, json, os, sys
sock = os.path.join(sys.argv[1], "keykoid.sock")
class U(http.client.HTTPConnection):
    def __init__(self): super().__init__("keykoi.local")
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.sock.connect(sock)
c = U(); c.request("POST", "/v1/sessions", json.dumps({"purpose": "keys-matrix"}), {"Content-Type": "application/json"})
print(json.loads(c.getresponse().read())["token"])
PY
)"

CHECKS=()
check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then CHECKS+=("PASS|$name|$actual"); log "PASS $name"
  else CHECKS+=("FAIL|$name|expected=$expected actual=$actual"); log "FAIL $name expected=$expected actual=$actual"; fi
}
stat_of() { curl -sS "http://127.0.0.1:$1/stats"; }

log "1) Bearer"
BEARER_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "http://$GW/gateway/billing/echo")
check "Bearer client request accepted" "200" "$BEARER_CODE"
check "upstream got the real Bearer key" "1" "$(stat_of "$UP_BEARER" | python3 -c 'import json,sys;print(json.load(sys.stdin)["matched"])')"

log "2) Custom API key header"
HEADER_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-Api-Key: $TOKEN" "http://$GW/gateway/inventory/echo")
check "API key client request accepted" "200" "$HEADER_CODE"
check "upstream got the real custom header value" "1" "$(stat_of "$UP_HEADER" | python3 -c 'import json,sys;print(json.load(sys.stdin)["header_matched"])')"

log "3) Basic auth credential"
BASIC_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOKEN" "http://$GW/gateway/basic/echo")
check "basic-auth request accepted" "200" "$BASIC_CODE"
check "upstream got the real Basic credential" "1" "$(stat_of "$UP_BASIC" | python3 -c 'import json,sys;print(json.load(sys.stdin)["matched"])')"

log "4) Git credential helper (git credential fill)"
cat > "$HOME_DIR/.gitconfig" <<EOF
[credential]
	helper = "!$BIN/keykoi helper git --binding bind_git"
EOF
GIT_OUT="$(printf 'protocol=https\nhost=example.com\n\n' | git credential fill 2>"$WORK/git.err" || true)"
check "git credential fill returns the username" "username=$GIT_USER" "$(printf '%s' "$GIT_OUT" | grep '^username=' || true)"
check "git credential fill returns the token as password" "password=$GIT_PASS" "$(printf '%s' "$GIT_OUT" | grep '^password=' || true)"
check "git helper did not leak KeyKoi token to stdout" "0" "$(printf '%s' "$GIT_OUT" | grep -c 'kks_' || true)"

log "5) 服务进程：仅注入会话令牌与网关地址（proxy 模式）"
cat > "$WORK/service.py" <<'PY'
import json, os, sys, urllib.request
base = os.environ["SERVICE_BASE_URL"]
key = os.environ["SERVICE_SESSION_TOKEN"]
if not key.startswith("kks_"):
    print("UNEXPECTED_KEY_PREFIX", file=sys.stderr); sys.exit(3)
req = urllib.request.Request(base + "/echo", headers={"Authorization": "Bearer " + key})
with urllib.request.urlopen(req) as resp:
    print(json.load(resp)["matched"])
PY
"$BIN/keykoi" --json run --mode proxy --route billing --exe "$(command -v python3)" \
  --env SERVICE_SESSION_TOKEN=runtime:session_token \
  --env SERVICE_BASE_URL=runtime:gateway_route \
  --report "$WORK/service-run.json" -- "$WORK/service.py" >"$WORK/service.out" 2>"$WORK/service.err" || true
check "service launched via proxy launcher gets a response" "True" "$(tail -1 "$WORK/service.out")"
check "service only holds the intermediary token" "0" "$(grep -c "$BEARER_KEY" "$WORK/service.out" || true)"
check "proxy launcher holds no credential lease" "" "$(python3 -c "import json;print(json.load(open('$WORK/service-run.json')).get('lease_id',''))" 2>/dev/null || echo missing)"
check "service requests reached the billing upstream" "2" "$(stat_of "$UP_BEARER" | python3 -c 'import json,sys;print(json.load(sys.stdin)["matched"])')"

log "6) negative paths"
NOAUTH=$(curl -sS -o /dev/null -w '%{http_code}' "http://$GW/gateway/billing/echo")
check "request without session token rejected" "401" "$NOAUTH"
RETIRED=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-Goog-Api-Key: $TOKEN" "http://$GW/gateway/billing/echo")
check "retired header alone cannot open a session" "401" "$RETIRED"
BADROUTE=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOKEN" "http://$GW/gateway/unregistered/echo")
check "unregistered route rejected" "404" "$BADROUTE"
LEAKED="$(for p in "$UP_BEARER" "$UP_HEADER" "$UP_BASIC"; do stat_of "$p" | python3 -c 'import json,sys;print(json.load(sys.stdin)["session_tokens"])'; done | paste -sd+ - | bc)"
check "no upstream ever saw the intermediary token" "0" "$LEAKED"

python3 - "$OUT_DIR/result.json" "${CHECKS[@]}" <<'PY'
import json, sys
out = {
  "phase": "keys-matrix",
  "environment": {
    "os": "macOS 27.0 arm64",
    "clients": "curl, Git, Python standard library",
    "upstream": "controlled mock upstreams (one per key shape)",
    "note": "未使用真实服务商密钥；所有密钥运行时生成。",
  },
  "checks": [],
}
for raw in sys.argv[2:]:
    st, name, detail = raw.split("|", 2)
    out["checks"].append({"status": st, "name": name, "detail": detail})
out["summary"] = {"total": len(out["checks"]), "failed": sum(1 for c in out["checks"] if c["status"] != "PASS")}
json.dump(out, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
print(f"checks={out['summary']['total']} failed={out['summary']['failed']}")
PY
grep -q '"failed": 0' "$OUT_DIR/result.json" || { log "keys matrix FAILED"; exit 1; }
log "keys matrix PASSED"
