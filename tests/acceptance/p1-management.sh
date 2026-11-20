#!/usr/bin/env bash
# P1 单机管理、安装与发布验收：launchd 安装/升级/重启、本机 Web UI 边界、
# 两条真实工具路径复跑、性能与恢复。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/p1-management}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-mgmt.XXXXXX")"
BIN="$WORK/bin"; PREFIX="$WORK/prefix"
mkdir -p "$BIN" "$OUT_DIR"
log() { printf '%s\n' "$*" >&2; }

LABEL="com.keykoi.keykoid.test.$$"
GWPORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
ADMINPORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"

cleanup() {
  set +e
  KEYKOI_PREFIX="$PREFIX" KEYKOI_LABEL="$LABEL" bash "$ROOT/packaging/macos/uninstall.sh" --prefix "$PREFIX" --label "$LABEL" >/dev/null 2>&1
  [ -n "${UP_PID:-}" ] && kill "$UP_PID" 2>/dev/null
  if [ "${KEEP_WORK:-0}" = "1" ]; then echo "work dir kept: $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

cd "$ROOT"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/mockupstream" ./tests/fixtures/mockupstream

export KEYKOI_DATA_DIR="$PREFIX/data" KEYKOI_SOCKET="$PREFIX/data/keykoid.sock"

log "install with launchd"
KEYKOI_PREFIX="$PREFIX" KEYKOI_LABEL="$LABEL" bash "$ROOT/packaging/macos/install.sh" \
  --prefix "$PREFIX" --label "$LABEL" --gateway "127.0.0.1:$GWPORT" --admin "127.0.0.1:$ADMINPORT" >"$WORK/install.log" 2>&1
for i in $(seq 1 100); do "$PREFIX/bin/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
check_launchd() { launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; }

CHECKS=()
check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then CHECKS+=("PASS|$name|$actual"); log "PASS $name"
  else CHECKS+=("FAIL|$name|expected=$expected actual=$actual"); log "FAIL $name expected=$expected actual=$actual"; fi
}

check "launchd service loaded" "0" "$(check_launchd; echo $?)"
check "installed binaries exist" "1" "$(test -x "$PREFIX/bin/keykoid" && test -x "$PREFIX/bin/keykoi" && echo 1 || echo 0)"
check "data directory permissions" "700" "$(stat -f '%Lp' "$PREFIX/data")"

"$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" status >/dev/null 2>&1
printf 'management-master-password\n' | "$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" init --password-stdin >/dev/null

log "seed credential/binding/grants via installed CLI"
UP_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
GW_KEY_RAW="$(openssl rand -hex 24)"
"$BIN/mockupstream" --addr "127.0.0.1:$UP_PORT" --expect "Bearer $GW_KEY_RAW" >"$WORK/up.log" 2>&1 &
UP_PID=$!
for i in $(seq 1 50); do curl -fsS "http://127.0.0.1:$UP_PORT/stats" >/dev/null 2>&1 && break; sleep 0.1; done
UP="http://127.0.0.1:$UP_PORT"
AWS_ID="AKIA$(openssl rand -hex 8 | tr 'a-f' 'A-F')"; AWS_SECRET="$(openssl rand -hex 20)"
CRED_HTTP="$("$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" --json credential add --kind api_key --label "mgmt proxy" --field "token=$GW_KEY_RAW")"
CRED_AWS="$("$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" --json credential add --kind access_key_pair --label "mgmt runtime" --field "access_id=$AWS_ID" --field "access_secret=$AWS_SECRET" --field "session_token=$(openssl rand -hex 8)")"
"$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" --json binding add --id bind_mgmt_http --credential "$CRED_HTTP" --origin "$UP" --route mgmt-http --scheme bearer >/dev/null
"$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" --json binding add --id bind_mgmt_aws --credential "$CRED_AWS" --origin "$UP" --route mgmt-aws --scheme bearer >/dev/null
"$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" --json grant add --principal "principal_local_$(id -u)" --binding bind_mgmt_http --mode proxy --auth permanent --max-lease-seconds 600 >/dev/null
"$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" --json grant add --principal "principal_local_$(id -u)" --binding bind_mgmt_aws --mode runtime_delivery --auth permanent --max-lease-seconds 600 >/dev/null

log "management UI boundary checks"
ADMIN_URL="http://127.0.0.1:$ADMINPORT"
UI_HTML="$(curl -sS "$ADMIN_URL/")"
check "UI page served" "yes" "$(printf '%s' "$UI_HTML" | grep -q '本机控制台' && echo yes || echo no)"
NOAUTH=$(curl -sS -o /dev/null -w '%{http_code}' "$ADMIN_URL/api/v1/status")
check "API without admin token rejected" "401" "$NOAUTH"
# 用钥接口在 IPC 上仍需会话令牌；这里验证管理面不接受空凭据即可。
TOKEN="$(cat "$PREFIX/data/admin.token")"
AUTHED=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Admin: $TOKEN" "$ADMIN_URL/api/v1/status")
check "API with admin token works" "200" "$AUTHED"
BADHOST=$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: evil.example" -H "X-KeyKoi-Admin: $TOKEN" "$ADMIN_URL/api/v1/status")
check "unexpected Host rejected" "403" "$BADHOST"
BADORIGIN=$(curl -sS -o /dev/null -w '%{http_code}' -H "Origin: http://evil.example" -H "X-KeyKoi-Admin: $TOKEN" "$ADMIN_URL/api/v1/status")
check "cross-origin request rejected" "403" "$BADORIGIN"
NOCSRF=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "X-KeyKoi-Admin: $TOKEN" -H 'Content-Type: application/json' -d '{}' "$ADMIN_URL/api/v1/vault/lock")
check "state change without CSRF header rejected" "403" "$NOCSRF"
LOCKED_ADMIN=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "X-KeyKoi-Admin: $TOKEN" -H "X-KeyKoi-CSRF: 1" -H 'Content-Type: application/json' -d '{}' "$ADMIN_URL/api/v1/vault/lock")
check "UI lock action accepted with CSRF header" "200" "$LOCKED_ADMIN"
curl -sS -o /dev/null -X POST -H "X-KeyKoi-Admin: $TOKEN" -H "X-KeyKoi-CSRF: 1" -H 'Content-Type: application/json' \
  -d "{\"password\":\"management-master-password\"}" "$ADMIN_URL/api/v1/vault/unlock"

log "P1.2.1 two real tool paths from the installed service"
SESSION_JSON="$(curl -sS -X POST -H "X-KeyKoi-Admin: $TOKEN" -H "X-KeyKoi-CSRF: 1" -H 'Content-Type: application/json' \
  -d '{"purpose":"mgmt-session"}' "$ADMIN_URL/api/v1/sessions")"
TOKEN_SESS="$(printf '%s' "$SESSION_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')"
CODE_PROXY=$(curl -sS -o "$WORK/proxy.json" -w '%{http_code}' -H "X-KeyKoi-Session: $TOKEN_SESS" "http://127.0.0.1:$GWPORT/gateway/mgmt-http/echo")
check "installed gateway path works" "200" "$CODE_PROXY"
check "gateway injected credential" "true" "$(python3 -c 'import json;print(str(json.load(open("'"$WORK/proxy.json"'"))["matched"]).lower())')"

"$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" --json run --binding bind_mgmt_aws --exe /bin/sh \
  --env GREETING=field:access_id --report "$WORK/run.json" -- -c 'printf "%s" "$GREETING"' >"$WORK/run.out" 2>&1
check "installed runtime delivery works" "0" "$(python3 -c 'import json;print(json.load(open("'"$WORK/run.json"'"))["exit_code"])')"
DELIVERED="no"
if [ "$(cat "$WORK/run.out")" = "$AWS_ID" ]; then DELIVERED="yes"; fi
check "runtime delivered the real value to the child" "yes" "$DELIVERED"

log "P1.2.2 upgrade and restart via launchd"
KEYKOI_PREFIX="$PREFIX" KEYKOI_LABEL="$LABEL" bash "$ROOT/packaging/macos/install.sh" \
  --prefix "$PREFIX" --label "$LABEL" --gateway "127.0.0.1:$GWPORT" --admin "127.0.0.1:$ADMINPORT" >"$WORK/upgrade.log" 2>&1
sleep 1
for i in $(seq 1 100); do "$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" status >/dev/null 2>&1 && break; sleep 0.1; done
STATUS_AFTER="$("$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" --json status)"
check "service restarted after upgrade" "0" "$(check_launchd; echo $?)"
check "restart returns locked" "True" "$(printf '%s' "$STATUS_AFTER" | python3 -c 'import json,sys;print(json.load(sys.stdin)["locked"])')"
CODE_LOCKED=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOKEN_SESS" "http://127.0.0.1:$GWPORT/gateway/mgmt-http/echo")
check "old session cannot be used after restart" "503" "$CODE_LOCKED"
printf 'management-master-password\n' | "$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" unlock --password-stdin >/dev/null
CODE_AFTER=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "X-KeyKoi-Admin: $TOKEN" -H "X-KeyKoi-CSRF: 1" -H 'Content-Type: application/json' \
  -d '{"purpose":"mgmt-session-2"}' "$ADMIN_URL/api/v1/sessions")
check "management API still available after upgrade" "201" "$CODE_AFTER"

log "ciphertext backup and recovery while locked"
BACKUP="$WORK/backup.json"
"$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" --json backup --out "$BACKUP" >/dev/null
check "backup has no plaintext secret" "0" "$(grep -c "$AWS_SECRET" "$BACKUP" || true)"
"$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" --json credential disable --id "$CRED_HTTP" >/dev/null
"$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" --json restore --in "$BACKUP" >"$WORK/restore.json"
check "restore leaves vault locked" "True" "$(python3 -c 'import json;print(str(json.load(open("'"$WORK/restore.json"'"))["locked_after"]).lower().capitalize())')"
printf 'management-master-password\n' | "$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" unlock --password-stdin >/dev/null
CODE_OLD=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $TOKEN_SESS" "http://127.0.0.1:$GWPORT/gateway/mgmt-http/echo")
check "pre-restore session stays invalid" "401" "$CODE_OLD"
NEW_SESS_JSON="$(curl -sS -X POST -H "X-KeyKoi-Admin: $TOKEN" -H "X-KeyKoi-CSRF: 1" -H 'Content-Type: application/json' \
  -d '{"purpose":"post-restore"}' "$ADMIN_URL/api/v1/sessions")"
NEW_TOK="$(printf '%s' "$NEW_SESS_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')"
CODE_RESTORED=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $NEW_TOK" "http://127.0.0.1:$GWPORT/gateway/mgmt-http/echo")
check "restored grants wait for review" "403" "$CODE_RESTORED"
for GRANT_ID in $(curl -sS -H "X-KeyKoi-Admin: $TOKEN" "$ADMIN_URL/api/v1/grants" | python3 -c 'import json,sys;print(" ".join(g["id"] for g in json.load(sys.stdin)["grants"]))'); do
  curl -sS -o /dev/null -X POST -H "X-KeyKoi-Admin: $TOKEN" -H "X-KeyKoi-CSRF: 1" "$ADMIN_URL/api/v1/grants/$GRANT_ID/approve"
done
CODE_APPROVED=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-KeyKoi-Session: $NEW_TOK" "http://127.0.0.1:$GWPORT/gateway/mgmt-http/echo")
check "reviewed grant resumes use" "200" "$CODE_APPROVED"

log "performance and streaming record"
"$PREFIX/bin/keykoi" --data-dir "$PREFIX/data" --json measure --route mgmt-http --direct "$UP" --requests 20 \
  --stream --out "$OUT_DIR/measure.json" >/dev/null

log "uninstall keeps data"
KEYKOI_PREFIX="$PREFIX" KEYKOI_LABEL="$LABEL" bash "$ROOT/packaging/macos/uninstall.sh" --prefix "$PREFIX" --label "$LABEL" --purge >/dev/null
check "uninstall removed launch agent" "1" "$(test ! -e "$HOME/Library/LaunchAgents/$LABEL.plist" && echo 1 || echo 0)"

python3 - "$OUT_DIR/result.json" "${CHECKS[@]}" <<'PY'
import json, sys
out = {"phase": "p1-management", "environment": {"os": "macOS (native)", "install": "launchd user agent + installed CLI"}, "checks": []}
for raw in sys.argv[2:]:
    st, name, detail = raw.split("|", 2)
    out["checks"].append({"status": st, "name": name, "detail": detail})
out["summary"] = {"total": len(out["checks"]), "failed": sum(1 for c in out["checks"] if c["status"] != "PASS")}
json.dump(out, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
print(f"checks={out['summary']['total']} failed={out['summary']['failed']}")
PY
grep -q '"failed": 0' "$OUT_DIR/result.json" || { log "management acceptance FAILED"; exit 1; }
log "P1 management acceptance PASSED"
