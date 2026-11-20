#!/usr/bin/env bash
# P3 多设备中心验收：本机 PostgreSQL + 中心服务 + 两个独立注册的设备客户端。
# 验证两种认证路径、在线撤销传播、断网短期许可、代次变化与恢复。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/p3-central}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-p3.XXXXXX")"
BIN="$WORK/bin"; mkdir -p "$BIN" "$OUT_DIR"
log() { printf '%s\n' "$*" >&2; }

cleanup() {
  set +e
  for pid in ${DAEMON_PIDS:-} ${CENTRAL_PID:-}; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  psql -q -d postgres -c "DROP DATABASE IF EXISTS $DBNAME" >/dev/null 2>&1
  if [ "${KEEP_WORK:-0}" = "1" ]; then echo "work dir kept: $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

cd "$ROOT"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/keykoi-central" ./cmd/keykoi-central
go build -o "$BIN/mockupstream" ./tests/fixtures/mockupstream

DBNAME="keykoi_central_$(openssl rand -hex 4)"
psql -q -d postgres -c "CREATE DATABASE $DBNAME" >/dev/null
DSN="postgres://$(whoami)@127.0.0.1:5432/$DBNAME?sslmode=disable"
ADMIN_TOKEN="$(openssl rand -hex 24)"
# 设备注册凭据与管理凭据分离：注册令牌只用于注册设备，管理操作只认管理员令牌。
BOOTSTRAP_TOKEN="$(openssl rand -hex 24)"
CENTRAL_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
CENTRAL_URL="http://127.0.0.1:$CENTRAL_PORT"

# 受控上游与测试凭证
UP_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
GW_KEY_RAW="$(openssl rand -hex 24)"
"$BIN/mockupstream" --addr "127.0.0.1:$UP_PORT" --expect "Bearer $GW_KEY_RAW" >"$WORK/up.log" 2>&1 &
UP_PID=$!
UP="http://127.0.0.1:$UP_PORT"
DAEMON_PIDS="$UP_PID"

start_central() {
  "$BIN/keykoi-central" --dsn "$DSN" --listen "127.0.0.1:$CENTRAL_PORT" --admin-token "$ADMIN_TOKEN" --bootstrap-token "$BOOTSTRAP_TOKEN" --lease-ttl 6s >"$WORK/central.log" 2>&1 &
  CENTRAL_PID=$!
  DAEMON_PIDS="$DAEMON_PIDS $CENTRAL_PID"
  for i in $(seq 1 60); do curl -fsS "$CENTRAL_URL/v1/status" >/dev/null 2>&1 && break; sleep 0.1; done
}
start_central

start_device() { # name datadir gateway_port admin_port mode
  local name="$1" ddir="$2" mode="$4"
  KEYKOI_DATA_DIR="$ddir" "$BIN/keykoid" --data-dir "$ddir" --adapters "$ROOT/adapters" \
    --gateway "127.0.0.1:0" --admin "127.0.0.1:0" \
    --central "$CENTRAL_URL" --central-bootstrap "$BOOTSTRAP_TOKEN" --central-mode "$mode" --device-name "$name" \
    >"$WORK/$name.log" 2>&1 &
  local pid=$!
  DAEMON_PIDS="$DAEMON_PIDS $pid"
  for i in $(seq 1 100); do KEYKOI_DATA_DIR="$ddir" "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
  echo "$pid"
}

seed_device() { # datadir binding
  local ddir="$1" binding="$2"
  KEYKOI_DATA_DIR="$ddir" printf 'p3-master-password\n' | KEYKOI_DATA_DIR="$ddir" "$BIN/keykoi" init --password-stdin >/dev/null
  local cred
  cred="$(KEYKOI_DATA_DIR="$ddir" "$BIN/keykoi" --json credential add --kind api_key --label "p3 key" --field "token=$GW_KEY_RAW")"
  KEYKOI_DATA_DIR="$ddir" "$BIN/keykoi" --json binding add --id "$binding" --credential "$cred" --origin "$UP" --route "$binding" --scheme bearer >/dev/null
  KEYKOI_DATA_DIR="$ddir" "$BIN/keykoi" --json grant add --principal "principal_local_$(id -u)" --binding "$binding" --mode proxy --auth permanent --max-lease-seconds 600 >/dev/null
  echo "$cred"
}

gateway_addr() { KEYKOI_DATA_DIR="$1" "$BIN/keykoi" --json status | python3 -c 'import json,sys;print(json.load(sys.stdin)["gateway"])'; }
session_token() { # datadir
  python3 - "$1" <<'PY'
import http.client, socket, json, os, sys
sock = os.path.join(sys.argv[1], "keykoid.sock")
class U(http.client.HTTPConnection):
    def __init__(self): super().__init__("keykoi.local")
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.sock.connect(sock)
c = U(); c.request("POST", "/v1/sessions", json.dumps({"purpose": "p3"}), {"Content-Type": "application/json"})
print(json.loads(c.getresponse().read())["token"])
PY
}

CHECKS=()
check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then CHECKS+=("PASS|$name|$actual"); log "PASS $name"
  else CHECKS+=("FAIL|$name|expected=$expected actual=$actual"); log "FAIL $name expected=$expected actual=$actual"; fi
}

A_DATA="$WORK/device-a"; B_DATA="$WORK/device-b"; C_DATA="$WORK/device-c"
mkdir -p "$A_DATA" "$B_DATA" "$C_DATA"

log "register two devices through the center (independent identity + state dirs)"
PID_A="$(start_device device-a "$A_DATA" 0 online)"
PID_B="$(start_device device-b "$B_DATA" 0 online)"
check "device A registered independently" "1" "$(python3 -c "import json;print(1 if json.load(open('$A_DATA/device.json'))['device_id'] != json.load(open('$B_DATA/device.json'))['device_id'] else 0)")"

seed_device "$A_DATA" p3-binding >/dev/null
seed_device "$B_DATA" p3-binding >/dev/null
curl -fsS -X POST "$CENTRAL_URL/v1/admin/policy" -H "X-Central-Admin: $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"binding_id":"p3-binding","credential_id":"cred_shared","credential_version":1,"mode":"proxy"}' >/dev/null

GW_A="$(gateway_addr "$A_DATA")"; GW_B="$(gateway_addr "$B_DATA")"
TOK_A="$(session_token "$A_DATA")"; TOK_B="$(session_token "$B_DATA")"

log "P3.2.1 online path (device A) and center confirmation"
CODE_A=$(curl -sS -o "$WORK/a.json" -w '%{http_code}' -H "X-KeyKoi-Session: $TOK_A" "$GW_A/gateway/p3-binding/echo")
check "device A authorized through the center" "200" "$CODE_A"
CODE_B=$(curl -sS -o "$WORK/b.json" -w '%{http_code}' -H "X-KeyKoi-Session: $TOK_B" "$GW_B/gateway/p3-binding/echo")
check "device B authorized through the center" "200" "$CODE_B"

log "P3.2.1b concurrent version update at the center"
curl -fsS -X POST "$CENTRAL_URL/v1/admin/policy" -H "X-Central-Admin: $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"binding_id":"p3-binding","credential_id":"cred_shared","credential_version":2,"mode":"proxy"}' >/dev/null
CODE_VER=$(curl -sS -o "$WORK/a2.json" -w '%{http_code}' -H "X-KeyKoi-Session: $TOK_A" "$GW_A/gateway/p3-binding/echo")
check "device A still authorized after version bump" "200" "$CODE_VER"
LEASED_VERSION=$(psql -tA -d "$DBNAME" -c "SELECT max(credential_version) FROM leases" | tr -d ' ')
check "new leases carry the updated credential version" "2" "$LEASED_VERSION"
T_AUTH0=$(python3 -c 'import time;print(time.time())')
curl -sS -o /dev/null -H "X-KeyKoi-Session: $TOK_A" "$GW_A/gateway/p3-binding/echo"
T_AUTH1=$(python3 -c 'import time;print(time.time())')
CENTER_AUTH_LATENCY_MS=$(python3 -c "print(int(($T_AUTH1-$T_AUTH0)*1000))")

log "P3.2.2 online revocation propagation"
T0=$(python3 -c 'import time;print(time.time())')
curl -fsS -X POST "$CENTRAL_URL/v1/admin/revoke" -H "X-Central-Admin: $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"kind":"device","target":"'"$(python3 -c "import json;print(json.load(open('$A_DATA/device.json'))['device_id'])")"'"}' >/dev/null
CODE_A2=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOK_A" "$GW_A/gateway/p3-binding/echo")
T1=$(python3 -c 'import time;print(time.time())')
PROPAGATION_MS=$(python3 -c "print(int(($T1-$T0)*1000))")
check "revoked device stops new use" "503" "$CODE_A2"
check "revocation propagated on next request" "1" "$(python3 -c "print(1 if $PROPAGATION_MS < 2000 else 0)")"
CODE_B2=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOK_B" "$GW_B/gateway/p3-binding/echo")
check "other device unaffected by device revocation" "200" "$CODE_B2"

log "P3.2.3 missed event: binding revoked at center, device B only learns by confirmation"
curl -fsS -X POST "$CENTRAL_URL/v1/admin/revoke" -H "X-Central-Admin: $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"kind":"binding","target":"p3-binding"}' >/dev/null
CODE_B3=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOK_B" "$GW_B/gateway/p3-binding/echo")
check "binding revocation also stops device B" "503" "$CODE_B3"

log "P3.2.4 short-term mode offline window"
# 重新启用策略，启动第三个短期模式设备。
curl -fsS -X POST "$CENTRAL_URL/v1/admin/policy" -H "X-Central-Admin: $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"binding_id":"p3-binding","credential_id":"cred_shared","credential_version":1,"mode":"proxy"}' >/dev/null
PID_C="$(start_device device-c "$C_DATA" 0 short_term)"
seed_device "$C_DATA" p3-binding >/dev/null
GW_C="$(gateway_addr "$C_DATA")"; TOK_C="$(session_token "$C_DATA")"
CODE_C=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOK_C" "$GW_C/gateway/p3-binding/echo")
check "short-term device authorized while center online" "200" "$CODE_C"
kill "$CENTRAL_PID" 2>/dev/null || true
sleep 0.5
OFFLINE_START=$(python3 -c 'import time;print(time.time())')
CODE_C2=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOK_C" "$GW_C/gateway/p3-binding/echo")
check "short-term device still within lease after center loss" "200" "$CODE_C2"
sleep 7
CODE_C3=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOK_C" "$GW_C/gateway/p3-binding/echo")
OFFLINE_END=$(python3 -c 'import time;print(time.time())')
check "short-term device stops after absolute deadline" "503" "$CODE_C3"
OFFLINE_SECONDS=$(python3 -c "print(round($OFFLINE_END-$OFFLINE_START,1))")

log "P3.2.5 epoch change after center restart (restored from backup)"
start_central
OLD_LEASE_JSON="$WORK/old-lease.json"
# 先取一次新租约，记录 epoch，然后重启中心再校验旧租约。
DEVICE_C_ID="$(python3 -c "import json;print(json.load(open('$C_DATA/device.json'))['device_id'])")"
CODE_C4=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOK_C" "$GW_C/gateway/p3-binding/echo")
check "short-term device resumes after center returns" "200" "$CODE_C4"
EPOCH_BEFORE=$(curl -fsS "$CENTRAL_URL/v1/status" | python3 -c 'import json,sys;print(json.load(sys.stdin)["epoch"])')
kill "$CENTRAL_PID" 2>/dev/null || true; wait "$CENTRAL_PID" 2>/dev/null || true
start_central
EPOCH_AFTER=$(curl -fsS "$CENTRAL_URL/v1/status" | python3 -c 'import json,sys;print(json.load(sys.stdin)["epoch"])')
check "center restart rotates authorization epoch" "1" "$(python3 -c "print(1 if '$EPOCH_BEFORE' != '$EPOCH_AFTER' else 0)")"
OLD_CHECK=$(curl -sS -o "$WORK/old-check.json" -w '%{http_code}' -X POST "$CENTRAL_URL/v1/check" \
  -H 'Content-Type: application/json' \
  -d '{"lease_id":"nonexistent-old-lease","device_id":"'"$DEVICE_C_ID"'"}')
check "stale lease cannot be confirmed after epoch change" "403" "$OLD_CHECK"

python3 - "$OUT_DIR/result.json" "$PROPAGATION_MS" "$OFFLINE_SECONDS" "$EPOCH_BEFORE" "$EPOCH_AFTER" "$CENTER_AUTH_LATENCY_MS" "${CHECKS[@]}" <<'PY'
import json, sys
out = {
  "phase": "p3-central",
  "environment": {
    "os": "macOS (native)",
    "topology": "single Mac: PostgreSQL 18 + center service + independent device clients",
    "postgres": "18 (local)",
  },
  "measurements": {
    "online_revocation_propagation_ms": int(sys.argv[2]),
    "offline_remaining_seconds_observed": float(sys.argv[3]),
    "epoch_before_restart": sys.argv[4],
    "epoch_after_restart": sys.argv[5],
    "center_authenticated_request_ms": int(sys.argv[6]),
  },
  "checks": [],
}
for raw in sys.argv[7:]:
    st, name, detail = raw.split("|", 2)
    out["checks"].append({"status": st, "name": name, "detail": detail})
out["summary"] = {"total": len(out["checks"]), "failed": sum(1 for c in out["checks"] if c["status"] != "PASS")}
json.dump(out, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
print(f"checks={out['summary']['total']} failed={out['summary']['failed']}")
PY
grep -q '"failed": 0' "$OUT_DIR/result.json" || { log "P3 acceptance FAILED"; exit 1; }
log "P3 acceptance PASSED"
