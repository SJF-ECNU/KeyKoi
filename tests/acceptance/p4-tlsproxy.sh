#!/usr/bin/env bash
# P4 验收：工具级受信 HTTPS 代理。
#
# 拓扑：
#   curl --proxy http://127.0.0.1:<proxy> --cacert <proxy CA> https://api.keykoi.test:<port>/echo
#     -> 代理校验登记域名与上游证书、终止客户端 TLS、注入认证头
#     -> 受控 HTTPS 上游（自签 CA）
# 受控环境不改 /etc/hosts：代理通过 --resolve api.keykoi.test=127.0.0.1 把登记域名
# 解析到本机，TLS 的 ServerName 与证书校验仍按登记域名进行（curl 侧只看到 CONNECT 目标）。
#
# 全部凭证在运行时随机生成；CA 私钥只写入临时目录并限制为 0600。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/p4-tlsproxy}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-p4-tlsproxy.XXXXXX")"
BIN="$WORK/bin"
mkdir -p "$BIN" "$OUT_DIR"

log() { printf '%s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

cleanup() {
  set +e
  [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  [ -n "${UP_GOOD_PID:-}" ] && kill "$UP_GOOD_PID" 2>/dev/null
  [ -n "${UP_BAD_PID:-}" ] && kill "$UP_BAD_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

cd "$ROOT"
log "building binaries"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/tlsupstream" ./tests/fixtures/tlsupstream

DATA="$WORK/data"
mkdir -p "$DATA"
export KEYKOI_DATA_DIR="$DATA"
UID_NUM="$(id -u)"
CLIENT_PRINCIPAL="principal_local_$UID_NUM"

# 运行时生成的凭证与主密码，不使用任何真实密钥。
PROXY_TOKEN="$(openssl rand -hex 24)"
MASTER_PW="$(openssl rand -hex 16)"
GOOD_HOST="api.keykoi.test"
BAD_HOST="bad.keykoi.test"
UNREGISTERED_HOST="unregistered.keykoi.test"

log "starting controlled HTTPS upstreams"
"$BIN/tlsupstream" --addr 127.0.0.1:0 --hostname "$GOOD_HOST" \
  --ca-dir "$WORK/up-good-ca" --addr-file "$WORK/up-good.addr" \
  --expect "Bearer $PROXY_TOKEN" >"$WORK/up-good.log" 2>&1 &
UP_GOOD_PID=$!
"$BIN/tlsupstream" --addr 127.0.0.1:0 --hostname "$BAD_HOST" \
  --ca-dir "$WORK/up-bad-ca" --addr-file "$WORK/up-bad.addr" \
  --expect "Bearer $PROXY_TOKEN" >"$WORK/up-bad.log" 2>&1 &
UP_BAD_PID=$!
for i in $(seq 1 100); do
  [ -s "$WORK/up-good.addr" ] && [ -s "$WORK/up-bad.addr" ] && break
  sleep 0.1
done
[ -s "$WORK/up-good.addr" ] || fail "good upstream did not start"
[ -s "$WORK/up-bad.addr" ] || fail "bad upstream did not start"
GOOD_ADDR="$(cat "$WORK/up-good.addr")"
BAD_ADDR="$(cat "$WORK/up-bad.addr")"
GOOD_PORT="${GOOD_ADDR##*:}"
BAD_PORT="${BAD_ADDR##*:}"
GOOD_ORIGIN="https://$GOOD_HOST:$GOOD_PORT"
BAD_ORIGIN="https://$BAD_HOST:$BAD_PORT"
log "good-upstream=$GOOD_ORIGIN bad-upstream=$BAD_ORIGIN"

log "starting keykoid (encrypted sqlite vault)"
"$BIN/keykoid" --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for i in $(seq 1 100); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
"$BIN/keykoi" status >/dev/null 2>&1 || fail "keykoid did not become reachable"

log "initializing vault and seeding proxy grant"
printf '%s\n' "$MASTER_PW" | "$BIN/keykoi" init --password-stdin >/dev/null
CRED="$("$BIN/keykoi" --json credential add --kind api_key --label "p4 tls upstream key" --field "token=$PROXY_TOKEN")"
[ -n "$CRED" ] || fail "could not create credential"
"$BIN/keykoi" --json binding add --id bind_p4_tls_good --credential "$CRED" \
  --origin "$GOOD_ORIGIN" --route p4-tls-good --scheme bearer >/dev/null
"$BIN/keykoi" --json binding add --id bind_p4_tls_bad --credential "$CRED" \
  --origin "$BAD_ORIGIN" --route p4-tls-bad --scheme bearer >/dev/null
"$BIN/keykoi" --json grant add --principal "$CLIENT_PRINCIPAL" --binding bind_p4_tls_good \
  --mode proxy --max-lease-seconds 600 --auth permanent >/dev/null
"$BIN/keykoi" --json grant add --principal "$CLIENT_PRINCIPAL" --binding bind_p4_tls_bad \
  --mode proxy --max-lease-seconds 600 --auth permanent >/dev/null

log "starting keykoi tls-proxy"
# 代理不再本地解锁密钥库：用钥决定交给运行中的 keykoid（锁定、验证与中心策略统一生效）。
"$BIN/keykoi" --data-dir "$DATA" tls-proxy \
  --binding bind_p4_tls_good --binding bind_p4_tls_bad \
  --listen 127.0.0.1:0 --ca-dir "$WORK/proxy-ca" \
  --upstream-ca "$WORK/up-good-ca/ca.pem" \
  --resolve "$GOOD_HOST=127.0.0.1" --resolve "$BAD_HOST=127.0.0.1" \
  >"$WORK/proxy.out" 2>"$WORK/proxy.log" &
PROXY_PID=$!
for i in $(seq 1 100); do
  grep -q '^listen=' "$WORK/proxy.out" 2>/dev/null && break
  kill -0 "$PROXY_PID" 2>/dev/null || fail "tls-proxy exited early: $(tail -5 "$WORK/proxy.log" | tr '\n' ' ')"
  sleep 0.1
done
PROXY_CA="$(sed -n 's/^ca_certificate=//p' "$WORK/proxy.out" | head -1)"
PROXY_ADDR="$(sed -n 's/^listen=//p' "$WORK/proxy.out" | head -1)"
[ -n "$PROXY_CA" ] && [ -f "$PROXY_CA" ] || fail "proxy did not print its CA certificate path"
[ -n "$PROXY_ADDR" ] || fail "proxy did not print its listen address"
PROXY_PORT="${PROXY_ADDR##*:}"
PROXY_URL="http://$PROXY_ADDR"
PROXY_TOKEN_FILE="$(sed -n 's/^proxy_token_file=//p' "$WORK/proxy.out" | head -1)"
[ -n "$PROXY_TOKEN_FILE" ] && [ -f "$PROXY_TOKEN_FILE" ] || fail "proxy did not provide a token file"
PROXY_CURL_CONFIG="$WORK/proxy.curlrc"
(umask 077; printf 'proxy-user = "keykoi:%s"\n' "$(cat "$PROXY_TOKEN_FILE")" >"$PROXY_CURL_CONFIG")
log "proxy=$PROXY_URL proxy-ca=$PROXY_CA"

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

json_field() { # file dotted.path
  python3 - "$1" "$2" <<'PY'
import json, sys
try:
    value = json.load(open(sys.argv[1]))
    for part in sys.argv[2].split("."):
        value = value[part]
except Exception as exc:  # noqa: BLE001 - 验收脚本需要可读的失败原因
    print(f"unreadable:{exc}")
else:
    print(str(value).lower() if isinstance(value, bool) else value)
PY
}

stats_field() { # ca-file host port field
  curl -sS --max-time 10 --noproxy '*' --cacert "$1" --resolve "$2:$3:127.0.0.1" \
    "https://$2:$3/stats" >"$WORK/stats.json" 2>"$WORK/stats.err" || \
    { printf 'unreachable'; return; }
  json_field "$WORK/stats.json" "$4"
}

log "P4.2.1 合法链路：curl 经代理访问已登记域名"
curl -sS --max-time 15 --config "$PROXY_CURL_CONFIG" --proxy "$PROXY_URL" --cacert "$PROXY_CA" \
  "https://$GOOD_HOST:$GOOD_PORT/echo?a=1&a=2" >"$WORK/legal.json" 2>"$WORK/legal.err" || \
  fail "legal request failed: $(cat "$WORK/legal.err")"
check "proxy injects real credential on registered domain" "true" "$(json_field "$WORK/legal.json" matched)"
check "proxy preserves query" "a=1&a=2" "$(json_field "$WORK/legal.json" query)"
check "proxy strips internal headers" "false" "$(json_field "$WORK/legal.json" keykoi_header_seen)"
CHECK_RESULTS+=("INFO|legal-response|$(tr -d '\n' <"$WORK/legal.json" | head -c 400)")

log "P4.2.2 未登记域名：CONNECT 被拒绝，不注入凭证"
set +e
curl -sS --max-time 10 --config "$PROXY_CURL_CONFIG" --proxy "$PROXY_URL" --cacert "$PROXY_CA" \
  "https://$UNREGISTERED_HOST:443/echo" >"$WORK/unregistered.out" 2>"$WORK/unregistered.err"
UNREGISTERED_EXIT=$?
set -e
if [ "$UNREGISTERED_EXIT" -ne 0 ] && grep -Eq '403|CONNECT' "$WORK/unregistered.err"; then
  check "unregistered domain CONNECT rejected" "ok" "ok"
else
  check "unregistered domain CONNECT rejected" "ok" "exit=$UNREGISTERED_EXIT $(tr '\n' ' ' <"$WORK/unregistered.err" | head -c 200)"
fi
check "rejection is reported without injection" "logged" "$({ grep -c 'not registered for this proxy' "$WORK/keykoid.log" 2>/dev/null || true; } | awk '{print ($1 > 0) ? "logged" : "missing"}')"
CHECK_RESULTS+=("INFO|unregistered-curl|exit=$UNREGISTERED_EXIT $(tr '\n' ' ' <"$WORK/unregistered.err" | head -c 300)")

log "P4.2.3 客户端不信任代理 CA（等同证书固定/未安装信任）"
set +e
curl -sS --max-time 15 --config "$PROXY_CURL_CONFIG" --proxy "$PROXY_URL" --cacert "$WORK/up-good-ca/ca.pem" \
  "https://$GOOD_HOST:$GOOD_PORT/echo" >"$WORK/untrusted.out" 2>"$WORK/untrusted.err"
UNTRUSTED_EXIT=$?
set -e
if [ "$UNTRUSTED_EXIT" -ne 0 ] && grep -qi 'certificate' "$WORK/untrusted.err"; then
  check "client without proxy CA trust fails verification" "verified_failure" "verified_failure"
else
  check "client without proxy CA trust fails verification" "verified_failure" "exit=$UNTRUSTED_EXIT $(tr '\n' ' ' <"$WORK/untrusted.err" | head -c 200)"
fi
check "untrusted client recorded as unsupported" "recorded" \
  "$({ grep -c 'recorded as unsupported' "$WORK/keykoid.log" 2>/dev/null || true; } | awk '{print ($1 > 0) ? "recorded" : "missing"}')"
CHECK_RESULTS+=("INFO|untrusted-ca-curl|exit=$UNTRUSTED_EXIT $(tr '\n' ' ' <"$WORK/untrusted.err" | head -c 300)")

log "P4.2.4 上游证书错误：在 CONNECT 阶段终止，凭证不离开代理"
set +e
curl -sS --max-time 15 --config "$PROXY_CURL_CONFIG" --proxy "$PROXY_URL" --cacert "$PROXY_CA" \
  "https://$BAD_HOST:$BAD_PORT/echo" >"$WORK/bad.out" 2>"$WORK/bad.err"
BAD_EXIT=$?
set -e
if [ "$BAD_EXIT" -ne 0 ] && grep -q '502' "$WORK/bad.err"; then
  check "invalid upstream certificate terminates CONNECT" "terminated_with_502" "terminated_with_502"
else
  check "invalid upstream certificate terminates CONNECT" "terminated_with_502" "exit=$BAD_EXIT $(tr '\n' ' ' <"$WORK/bad.err" | head -c 200)"
fi
check "upstream TLS rejection is identifiable" "logged" \
  "$({ grep -c 'upstream_tls_invalid' "$WORK/keykoid.log" 2>/dev/null || true; } | awk '{print ($1 > 0) ? "logged" : "missing"}')"
CHECK_RESULTS+=("INFO|upstream-rejection-detail|$(grep 'upstream_tls_invalid' "$WORK/keykoid.log" | head -1 | head -c 300)")
CHECK_RESULTS+=("INFO|upstream-error-curl|exit=$BAD_EXIT $(tr '\n' ' ' <"$WORK/bad.err" | head -c 300)")

log "P4.2.5 上游与传输侧核对"
check "upstream never sees intermediary session token" "0" "$(stats_field "$WORK/up-good-ca/ca.pem" "$GOOD_HOST" "$GOOD_PORT" session_tokens)"
check "invalid-upstream target received no request" "0" "$(stats_field "$WORK/up-bad-ca/ca.pem" "$BAD_HOST" "$BAD_PORT" requests)"
check "registered target received exactly the legal request" "1" "$(stats_field "$WORK/up-good-ca/ca.pem" "$GOOD_HOST" "$GOOD_PORT" requests)"
if grep -qF "$PROXY_TOKEN" "$WORK/proxy.log"; then
  check "proxy log contains no credential value" "absent" "leaked"
else
  check "proxy log contains no credential value" "absent" "absent"
fi
if grep -rqF "$PROXY_TOKEN" "$DATA" 2>/dev/null; then
  check "data directory contains no plaintext credential" "absent" "leaked"
else
  check "data directory contains no plaintext credential" "absent" "absent"
fi

log "P4.2.6 CA 私钥与清理"
check "CA private key is 0600" "600" "$(stat -f '%Lp' "$WORK/proxy-ca/ca-key.pem")"
check "CA public certificate is 0644" "644" "$(stat -f '%Lp' "$PROXY_CA")"
check "CA directory is 0700" "700" "$(stat -f '%Lp' "$WORK/proxy-ca")"

kill -TERM "$PROXY_PID" 2>/dev/null || true
set +e
wait "$PROXY_PID"
PROXY_EXIT=$?
set -e
PROXY_PID=""
check "SIGTERM exits cleanly" "0" "$PROXY_EXIT"
LISTEN_STATE="$(python3 - "$PROXY_PORT" <<'PY'
import socket, sys
s = socket.socket()
s.settimeout(1)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    print("closed")
else:
    print("open")
finally:
    s.close()
PY
)"
check "proxy listener is closed after SIGTERM" "closed" "$LISTEN_STATE"

cp "$WORK/proxy.log" "$OUT_DIR/proxy.log" 2>/dev/null || true

HOST_OS="$(sw_vers -productVersion 2>/dev/null || uname -s)"
ARCH="$(uname -m)"

python3 - "$OUT_DIR/result.json" "$HOST_OS" "$ARCH" "$PROXY_URL" "$GOOD_ORIGIN" "$BAD_ORIGIN" "$PROXY_CA" "$WORK/up-good-ca/ca.pem" "${CHECK_RESULTS[@]}" <<'PY'
import json, sys
out = {
  "phase": "p4-tlsproxy",
  "environment": {
    "os": f"macOS {sys.argv[2]}",
    "arch": sys.argv[3],
    "upstream": "tests/fixtures/tlsupstream (in-memory, self-signed test CA, no credential persistence)",
    "vault": "encrypted sqlite vault via keykoid + keykoi init",
    "artifacts_note": "CA 私钥、临时凭证与工作目录在退出时删除；此目录只保留结果与代理日志（不含秘密）。",
  },
  "topology": {
    "proxy": sys.argv[4],
    "registered_good": sys.argv[5],
    "registered_bad_certificate": sys.argv[6],
    "proxy_ca": sys.argv[7],
    "trusted_upstream_ca": sys.argv[8],
    "dns_note": "curl 通过 HTTPS 代理 CONNECT 到登记域名；代理用 --resolve 把登记域名映射到 127.0.0.1，TLS ServerName 与证书校验仍按登记域名进行。未修改 /etc/hosts。",
  },
  "checks": [],
  "unsupported": [
    {
      "case": "certificate_pinning",
      "status": "unsupported",
      "detail": "工具固定上游证书或缺少独立信任配置时，客户端会在代理终止 TLS 后拒绝代理签发证书；代理记录 client_tls_failures 并明确提示，不执行注入。",
    },
    {
      "case": "client_without_proxy_ca_trust",
      "status": "unsupported",
      "detail": "客户端未安装/不信任本机 CA 时验证失败（验收用 --cacert 不匹配复现），代理无法为该客户端提供认证。",
    },
  ],
}
for raw in sys.argv[9:]:
    parts = raw.split("|", 2)
    out["checks"].append({
        "status": parts[0],
        "name": parts[1],
        "detail": parts[2] if len(parts) > 2 else "",
    })
failed = [c for c in out["checks"] if c["status"] == "FAIL"]
informational = [c for c in out["checks"] if c["status"] == "INFO"]
out["summary"] = {"total": len(out["checks"]), "failed": len(failed), "informational": len(informational)}
with open(sys.argv[1], "w") as fh:
    json.dump(out, fh, indent=2, ensure_ascii=False)
print(f"checks={out['summary']['total']} failed={len(failed)}")
PY

if grep -q '"failed": 0' "$OUT_DIR/result.json"; then
  log "P4 tls-proxy acceptance PASSED"
else
  log "P4 tls-proxy acceptance has failures; see $OUT_DIR/result.json"
  exit 1
fi
