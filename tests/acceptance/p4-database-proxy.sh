#!/usr/bin/env bash
# P4 验收：PostgreSQL 协议代理。真实 psql 客户端 + 真实 PostgreSQL 18 上游。
#
# 覆盖：客户端用 KeyKoi 会话令牌认证、代理向上游完成 SCRAM-SHA-256 认证、
# 拒绝无许可/错误令牌、客户端侧 TLS 不支持路径、CancelRequest 转发、连接关闭，
# 以及上游 TLS（sslmode=require + 证书校验，临时开启 SSL 的真实 PostgreSQL 实例）。
# 测试角色与库在运行时创建，密码运行时随机生成，不写入文档或日志；默认在结束时删除。
#   KEEP_DB=1     保留主实例上的测试库与角色（便于人工复核）
#   DB_HOST/DB_PORT/ADMIN_DB  覆盖上游与管理员数据库（默认 127.0.0.1:5432/postgres）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/p4-database-proxy}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-p4db.XXXXXX")"
BIN="$WORK/bin"
mkdir -p "$BIN" "$OUT_DIR"

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
ADMIN_DB="${ADMIN_DB:-postgres}"
KEEP_DB="${KEEP_DB:-0}"
DB_NAME="keykoi_test"
ROLE_NAME="keykoi_test"
DB_DROPPED=0
PROXY_PIDS=()
PG_BIN_DIR="$(dirname "$(command -v psql)")"
INITDB="$PG_BIN_DIR/initdb"
PG_CTL="$PG_BIN_DIR/pg_ctl"
TLS_CLUSTER_DIR=""
TLS_SUMMARY="skipped: initdb/pg_ctl/openssl not available"

log() { printf '%s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

admin_psql() {
  psql -X -q -h "$DB_HOST" -p "$DB_PORT" -d "$ADMIN_DB" -v ON_ERROR_STOP=1 "$@"
}

drop_test_database() {
  [ "${DB_DROPPED}" = "1" ] && return 0
  set +e
  admin_psql >/dev/null 2>&1 <<SQL
DROP DATABASE IF EXISTS "$DB_NAME" WITH (FORCE);
DROP ROLE IF EXISTS "$ROLE_NAME";
SQL
  DB_DROPPED=1
  set -e
}

cleanup() {
  set +e
  for pid in "${PROXY_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  if [ -n "$TLS_CLUSTER_DIR" ] && [ -x "$PG_CTL" ]; then
    "$PG_CTL" -D "$TLS_CLUSTER_DIR/data" -m immediate stop >/dev/null 2>&1
  fi
  wait 2>/dev/null
  if [ "$KEEP_DB" != "1" ]; then
    drop_test_database
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

cd "$ROOT"
log "building binaries"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/pgxclient" ./tests/fixtures/dbproxy/pgxclient

command -v psql >/dev/null || fail "psql is required for this acceptance run"
psql -X -q -h "$DB_HOST" -p "$DB_PORT" -d "$ADMIN_DB" -tAc 'select 1' >/dev/null 2>&1 \
  || fail "cannot connect to PostgreSQL at $DB_HOST:$DB_PORT (database $ADMIN_DB)"

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

log "recording environment"
PSQL_VERSION="$(psql --version | head -1)"
PG_VERSION="$(psql -X -h "$DB_HOST" -p "$DB_PORT" -d "$ADMIN_DB" -tAc 'show server_version')"
PG_SSL="$(psql -X -h "$DB_HOST" -p "$DB_PORT" -d "$ADMIN_DB" -tAc 'show ssl')"
PG_PWENC="$(psql -X -h "$DB_HOST" -p "$DB_PORT" -d "$ADMIN_DB" -tAc 'show password_encryption')"
HOST_OS="$(sw_vers -productVersion 2>/dev/null || uname -s)"
ARCH="$(uname -m)"

log "creating dedicated test role and database (runtime random password)"
COLLISION="$(psql -X -h "$DB_HOST" -p "$DB_PORT" -d "$ADMIN_DB" -tAc \
  "select (select count(*) from pg_roles where rolname='$ROLE_NAME') + (select count(*) from pg_database where datname='$DB_NAME')")"
if [ "$COLLISION" != "0" ]; then
  SUFFIX="$(openssl rand -hex 3)"
  ROLE_NAME="keykoi_test_$SUFFIX"
  DB_NAME="keykoi_test_$SUFFIX"
  log "note: keykoi_test already exists; using $ROLE_NAME / $DB_NAME instead of dropping it"
fi
DB_PASSWORD="$(openssl rand -hex 24)"
printf "CREATE ROLE %s LOGIN PASSWORD '%s';\nCREATE DATABASE %s OWNER %s;\n" \
  "$ROLE_NAME" "$DB_PASSWORD" "$DB_NAME" "$ROLE_NAME" | admin_psql
AUTH_METHOD="$(psql -X -h "$DB_HOST" -p "$DB_PORT" -d "$ADMIN_DB" -tAc \
  "select case when rolpassword like 'SCRAM-SHA-256%' then 'scram-sha-256' when rolpassword like 'md5%' then 'md5' else 'other' end from pg_authid where rolname='$ROLE_NAME'")"
check "upstream role uses scram-sha-256" "scram-sha-256" "$AUTH_METHOD"

log "starting keykoid (temporary data dir, ephemeral ports)"
DATA="$WORK/data"
mkdir -p "$DATA"
export KEYKOI_DATA_DIR="$DATA"
"$BIN/keykoid" --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for _ in $(seq 1 80); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
"$BIN/keykoi" status >/dev/null 2>&1 || fail "keykoid did not start"

MASTER_PASSWORD="$(openssl rand -hex 16)"
printf '%s\n' "$MASTER_PASSWORD" | "$BIN/keykoi" init --password-stdin >/dev/null
unset MASTER_PASSWORD

log "seeding database credential, bindings and runtime_delivery grant"
CRED="$("$BIN/keykoi" --json credential add --kind database --label "p4 postgres" \
  --field "username=$ROLE_NAME" --field "password=$DB_PASSWORD" --field "database=$DB_NAME")"
[ -n "$CRED" ] || fail "credential was not created"
BINDING="bind_p4_pg"
BINDING_NOGRANT="bind_p4_pg_nogrant"
# Binding 只接受 http/https scheme：这里用 http://127.0.0.1:5432 作为上游地址占位，
# 数据库适配层把 origin 的 host:port 当作 PostgreSQL 连接地址，TLS 与库名另由参数/凭证决定。
"$BIN/keykoi" --json binding add --id "$BINDING" --credential "$CRED" \
  --origin "http://$DB_HOST:$DB_PORT" --route p4-pg --scheme basic \
  --username-field username --password-field password >/dev/null
"$BIN/keykoi" --json binding add --id "$BINDING_NOGRANT" --credential "$CRED" \
  --origin "http://$DB_HOST:$DB_PORT" --route p4-pg-nogrant --scheme basic \
  --username-field username --password-field password >/dev/null
"$BIN/keykoi" --json grant add --principal "principal_local_$(id -u)" \
  --binding "$BINDING" --mode runtime_delivery --auth permanent --max-lease-seconds 600 >/dev/null

start_proxy() { # binding out-prefix -> 设置 PROXY_PORT / PROXY_TOKEN
  local binding="$1" prefix="$2"
  "$BIN/keykoi" db-proxy --binding "$binding" --listen 127.0.0.1:0 --upstream-sslmode disable \
    >"$prefix.out" 2>"$prefix.err" &
  PROXY_PIDS+=($!)
  for _ in $(seq 1 80); do grep -q "session-token" "$prefix.out" 2>/dev/null && break; sleep 0.1; done
  grep -q "session-token" "$prefix.out" || fail "db-proxy for $binding did not print a session token"
  PROXY_PORT="$(grep -o 'listening 127\.0\.0\.1:[0-9]*' "$prefix.out" | head -1 | sed 's/.*://')"
  PROXY_TOKEN="$(grep -o 'kks_[A-Za-z0-9_-]*' "$prefix.out" | head -1)"
  [ -n "$PROXY_PORT" ] && [ -n "$PROXY_TOKEN" ] || fail "could not parse db-proxy startup output"
}

log "P4.1: 真实 psql 经代理连接上游 PostgreSQL"
start_proxy "$BINDING" "$WORK/proxy"
log "proxy listening on 127.0.0.1:$PROXY_PORT (binding=$BINDING)"
MAIN_PROXY_PORT="$PROXY_PORT"
MAIN_PROXY_TOKEN="$PROXY_TOKEN"

PSQL_CONN="host=$DB_HOST port=$MAIN_PROXY_PORT user=keykoi dbname=$DB_NAME sslmode=prefer connect_timeout=10"
SELECT_ONE="$(PGPASSWORD="$MAIN_PROXY_TOKEN" psql -X -tA -c 'select 1' "$PSQL_CONN" 2>"$WORK/select1.err" || true)"
check "psql select 1 through proxy" "1" "$SELECT_ONE"

IDENTITY="$(PGPASSWORD="$MAIN_PROXY_TOKEN" psql -X -tA -c \
  "select current_user || '|' || current_database()" "$PSQL_CONN" 2>>"$WORK/select1.err" || true)"
check "upstream identity is the registered database user" "$ROLE_NAME|$DB_NAME" "$IDENTITY"

SERVER_VERSION="$(PGPASSWORD="$MAIN_PROXY_TOKEN" psql -X -tA -c \
  "select current_setting('server_version')" "$PSQL_CONN" 2>>"$WORK/select1.err" || true)"
check "proxied query reaches PostgreSQL 18" "18" "$(printf '%s' "$SERVER_VERSION" | cut -d. -f1)"

# 直接以真实数据库密码登录，证明代理用的是真实 SCRAM 凭证而不是绕过上游认证。
DIRECT_ONE="$(PGPASSWORD="$DB_PASSWORD" psql -X -tA -c 'select 1' \
  "host=$DB_HOST port=$DB_PORT user=$ROLE_NAME dbname=$DB_NAME sslmode=prefer connect_timeout=10" 2>/dev/null || true)"
check "direct role login with real database password" "1" "$DIRECT_ONE"

# 真实 Go 驱动（pgx 扩展查询协议）经代理执行带参数的查询。
PGX_DSN="postgres://keykoi:$MAIN_PROXY_TOKEN@$DB_HOST:$MAIN_PROXY_PORT/$DB_NAME?sslmode=disable&connect_timeout=10"
PGX_RESULT="$("$BIN/pgxclient" --dsn "$PGX_DSN" --query 'select $1::int + 1' --value 41 2>"$WORK/pgx.err" || true)"
check "pgx extended-protocol query through proxy" "42" "$PGX_RESULT"

log "P4.2: 拒绝错误令牌、无许可与客户端 TLS"
set +e
PGPASSWORD="kks_wrong_token_for_acceptance" psql -X -tA -c 'select 1' "$PSQL_CONN" >"$WORK/wrong-token.out" 2>&1
WRONG_TOKEN_EXIT=$?
set -e
if [ "$WRONG_TOKEN_EXIT" -ne 0 ] && grep -q "not authorized" "$WORK/wrong-token.out"; then
  check "wrong session token rejected" "denied" "denied"
else
  check "wrong session token rejected" "denied" "exit=$WRONG_TOKEN_EXIT $(tail -1 "$WORK/wrong-token.out" | tr '\n' ' ')"
fi

start_proxy "$BINDING_NOGRANT" "$WORK/proxy-nogrant"
NO_GRANT_PORT="$PROXY_PORT"
NO_GRANT_TOKEN="$PROXY_TOKEN"
set +e
PGPASSWORD="$NO_GRANT_TOKEN" psql -X -tA -c 'select 1' \
  "host=$DB_HOST port=$NO_GRANT_PORT user=keykoi dbname=$DB_NAME sslmode=prefer connect_timeout=10" \
  >"$WORK/no-grant.out" 2>&1
NO_GRANT_EXIT=$?
set -e
if [ "$NO_GRANT_EXIT" -ne 0 ] && grep -q "not authorized" "$WORK/no-grant.out"; then
  check "binding without runtime_delivery grant rejected" "denied" "denied"
else
  check "binding without runtime_delivery grant rejected" "denied" "exit=$NO_GRANT_EXIT $(tail -1 "$WORK/no-grant.out" | tr '\n' ' ')"
fi

# 客户端侧 TLS 不在支持范围：代理对 SSLRequest 回 'N'，libpq 在 sslmode=require 时明确报错。
set +e
PGPASSWORD="$MAIN_PROXY_TOKEN" psql -X -tA -c 'select 1' \
  "host=$DB_HOST port=$MAIN_PROXY_PORT user=keykoi dbname=$DB_NAME sslmode=require connect_timeout=10" \
  >"$WORK/client-tls.out" 2>&1
CLIENT_TLS_EXIT=$?
set -e
if [ "$CLIENT_TLS_EXIT" -ne 0 ] && grep -q "does not support SSL" "$WORK/client-tls.out"; then
  check "client-side TLS reported as unsupported" "unsupported" "unsupported"
else
  check "client-side TLS reported as unsupported" "unsupported" "exit=$CLIENT_TLS_EXIT $(tail -1 "$WORK/client-tls.out" | tr '\n' ' ')"
fi

log "P4.3: 取消请求（psql Ctrl-C → CancelRequest 转发）"
set +e
PGPASSWORD="$MAIN_PROXY_TOKEN" python3 "$ROOT/tests/fixtures/dbproxy/cancel_pty.py" \
  --query "select pg_sleep(30);" --timeout 30 -- \
  psql -X -h "$DB_HOST" -p "$MAIN_PROXY_PORT" -U keykoi -d "$DB_NAME" \
  >"$WORK/cancel.out" 2>"$WORK/cancel.err"
CANCEL_EXIT=$?
set -e
check "cancel request forwarded to upstream" "0" "$CANCEL_EXIT"
if ! grep -q "canceling statement due to user request" "$WORK/cancel.out"; then
  CHECK_RESULTS+=("FAIL|cancel error surfaced to client|$(tail -2 "$WORK/cancel.err" | tr '\n' ' ')")
fi

log "P4.4: 连接关闭后上游会话释放"
LEFT="pending"
for _ in $(seq 1 50); do
  LEFT="$(psql -X -h "$DB_HOST" -p "$DB_PORT" -d "$ADMIN_DB" -tAc \
    "select count(*) from pg_stat_activity where usename='$ROLE_NAME'")"
  [ "$LEFT" = "0" ] && break
  sleep 0.1
done
check "no upstream session left open after client close" "0" "$LEFT"

log "P4.5: 秘密不落盘"
LEAKS=0
for f in "$WORK/proxy.out" "$WORK/proxy.err" "$WORK/keykoid.log" \
         "$WORK/proxy-nogrant.out" "$WORK/proxy-nogrant.err"; do
  if grep -qF "$DB_PASSWORD" "$f" 2>/dev/null; then
    LEAKS=$((LEAKS + 1))
    log "database password found in $f"
  fi
done
check "database password never printed to logs" "0" "$LEAKS"

log "P4.6: 上游 TLS（sslmode=require + 证书校验，真实 PostgreSQL）"
if [ -x "$INITDB" ] && [ -x "$PG_CTL" ] && command -v openssl >/dev/null 2>&1; then
  TLS_DIR="$WORK/tls"
  mkdir -p "$TLS_DIR/sock"
  TLS_PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
  "$INITDB" -D "$TLS_DIR/data" -U postgres --auth-local=trust --auth-host=scram-sha-256 -E UTF8 \
    >"$TLS_DIR/initdb.log" 2>&1 || fail "initdb failed for the temporary TLS cluster"
  openssl req -new -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.crt" \
    -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
    >"$TLS_DIR/openssl.log" 2>&1 || fail "openssl could not create the test certificate"
  chmod 600 "$TLS_DIR/server.key"
  TLS_CLUSTER_DIR="$TLS_DIR"
  "$PG_CTL" -D "$TLS_DIR/data" -l "$TLS_DIR/pg.log" -o \
    "-p $TLS_PORT -c listen_addresses=127.0.0.1 -c ssl=on -c ssl_cert_file=$TLS_DIR/server.crt -c ssl_key_file=$TLS_DIR/server.key -k $TLS_DIR/sock" \
    -w start >/dev/null 2>&1 || fail "temporary TLS cluster did not start"

  TLS_ROLE="keykoi_tls"
  TLS_DB="keykoi_tls"
  TLS_PASSWORD="$(openssl rand -hex 24)"
  printf "CREATE ROLE %s LOGIN PASSWORD '%s';\nCREATE DATABASE %s OWNER %s;\n" \
    "$TLS_ROLE" "$TLS_PASSWORD" "$TLS_DB" "$TLS_ROLE" \
    | psql -X -q -h "$TLS_DIR/sock" -p "$TLS_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1
  TLS_CRED="$("$BIN/keykoi" --json credential add --kind database --label "p4 postgres tls" \
    --field "username=$TLS_ROLE" --field "password=$TLS_PASSWORD" --field "database=$TLS_DB")"
  TLS_BINDING="bind_p4_pg_tls"
  "$BIN/keykoi" --json binding add --id "$TLS_BINDING" --credential "$TLS_CRED" \
    --origin "http://127.0.0.1:$TLS_PORT" --route p4-pg-tls --scheme basic \
    --username-field username --password-field password >/dev/null
  "$BIN/keykoi" --json grant add --principal "principal_local_$(id -u)" \
    --binding "$TLS_BINDING" --mode runtime_delivery --auth permanent --max-lease-seconds 600 >/dev/null

  # 正例：用私有 CA 校验证书，上游连接必须是 TLS。
  "$BIN/keykoi" db-proxy --binding "$TLS_BINDING" --listen 127.0.0.1:0 \
    --upstream-sslmode require --upstream-ca "$TLS_DIR/server.crt" \
    >"$WORK/proxy-tls.out" 2>"$WORK/proxy-tls.err" &
  PROXY_PIDS+=($!)
  for _ in $(seq 1 80); do grep -q "session-token" "$WORK/proxy-tls.out" 2>/dev/null && break; sleep 0.1; done
  TLS_PROXY_PORT="$(grep -o 'listening 127\.0\.0\.1:[0-9]*' "$WORK/proxy-tls.out" | head -1 | sed 's/.*://')"
  TLS_PROXY_TOKEN="$(grep -o 'kks_[A-Za-z0-9_-]*' "$WORK/proxy-tls.out" | head -1)"
  TLS_CONN="host=127.0.0.1 port=$TLS_PROXY_PORT user=keykoi dbname=$TLS_DB sslmode=disable connect_timeout=10"
  if [ -n "$TLS_PROXY_PORT" ]; then
    TLS_SSL="$(PGPASSWORD="$TLS_PROXY_TOKEN" psql -X -tA -c \
      "select ssl from pg_stat_ssl where pid = pg_backend_pid()" "$TLS_CONN" 2>"$WORK/proxy-tls.psql.err" || true)"
    TLS_VERSION="$(PGPASSWORD="$TLS_PROXY_TOKEN" psql -X -tA -c \
      "select version from pg_stat_ssl where pid = pg_backend_pid()" "$TLS_CONN" 2>>"$WORK/proxy-tls.psql.err" || true)"
    check "upstream TLS verified with private CA" "t" "$TLS_SSL"
    TLS_SUMMARY="upstream TLS active (${TLS_VERSION:-unknown}); certificate verified against a private CA"

    # 负例：同一上游、不信任其 CA 时必须拒绝，而不是降到明文。
    "$BIN/keykoi" db-proxy --binding "$TLS_BINDING" --listen 127.0.0.1:0 \
      --upstream-sslmode require >"$WORK/proxy-tls-untrusted.out" 2>"$WORK/proxy-tls-untrusted.err" &
    PROXY_PIDS+=($!)
    for _ in $(seq 1 80); do grep -q "session-token" "$WORK/proxy-tls-untrusted.out" 2>/dev/null && break; sleep 0.1; done
    UNTRUSTED_PORT="$(grep -o 'listening 127\.0\.0\.1:[0-9]*' "$WORK/proxy-tls-untrusted.out" | head -1 | sed 's/.*://')"
    UNTRUSTED_TOKEN="$(grep -o 'kks_[A-Za-z0-9_-]*' "$WORK/proxy-tls-untrusted.out" | head -1)"
    set +e
    PGPASSWORD="$UNTRUSTED_TOKEN" psql -X -tA -c 'select 1' \
      "host=127.0.0.1 port=$UNTRUSTED_PORT user=keykoi dbname=$TLS_DB sslmode=disable connect_timeout=10" \
      >"$WORK/tls-untrusted.out" 2>&1
    UNTRUSTED_EXIT=$?
    set -e
    if [ "$UNTRUSTED_EXIT" -ne 0 ] && grep -q "upstream connection failed" "$WORK/tls-untrusted.out"; then
      check "upstream TLS without trusted CA rejected" "denied" "denied"
    else
      check "upstream TLS without trusted CA rejected" "denied" "exit=$UNTRUSTED_EXIT $(tail -1 "$WORK/tls-untrusted.out" | tr '\n' ' ')"
    fi
  else
    check "upstream TLS verified with private CA" "t" "proxy did not start"
  fi
else
  log "skipping upstream TLS section: initdb/pg_ctl/openssl not available"
fi

log "cleaning up test database"
if [ "$KEEP_DB" = "1" ]; then
  log "KEEP_DB=1: keeping role $ROLE_NAME and database $DB_NAME"
else
  drop_test_database
  REMAINING="$(psql -X -h "$DB_HOST" -p "$DB_PORT" -d "$ADMIN_DB" -tAc \
    "select (select count(*) from pg_roles where rolname='$ROLE_NAME') + (select count(*) from pg_database where datname='$DB_NAME')")"
  check "test role and database removed" "0" "$REMAINING"
fi

log "writing result.json"
python3 - "$OUT_DIR/result.json" "$PSQL_VERSION" "$PG_VERSION" "$PG_SSL" "$PG_PWENC" "$HOST_OS" "$ARCH" \
  "$ROLE_NAME" "$DB_NAME" "$AUTH_METHOD" "$KEEP_DB" "$TLS_SUMMARY" "${CHECK_RESULTS[@]}" <<'PY'
import json, sys

args = sys.argv[1:]
(out_path, psql_version, pg_version, pg_ssl, pg_pwenc, host_os, arch,
 role, dbname, auth_method, keep_db, tls_summary) = args[:12]
checks = args[12:]

out = {
  "phase": "p4-database-proxy",
  "environment": {
    "os": f"macOS {host_os}" if host_os else "unknown",
    "arch": arch,
    "client_driver": psql_version,
    "upstream_server": f"PostgreSQL {pg_version}",
    "upstream_ssl": pg_ssl,
    "upstream_password_encryption": pg_pwenc,
    "upstream_role_auth": auth_method,
    "proxy_upstream_sslmode": "disable for the plaintext checks; require + --upstream-ca for the TLS section",
    "upstream_tls_evidence": tls_summary,
  },
  "protocol": {
    "client_auth": "AuthenticationCleartextPassword carrying the KeyKoi session token (loopback only)",
    "client_user": "keykoi",
    "upstream_auth": ["scram-sha-256", "md5", "cleartext"],
    "upstream_tls": "sslmode=disable|prefer|require; prefer/require verify certificate chain and hostname, optional --upstream-ca",
    "lifecycle": ["CancelRequest forwarding", "connection close", "SQLSTATE error frames"],
    "unsupported": [
      "client-side TLS (SSLRequest answered with 'N')",
      "SCRAM-SHA-256-PLUS channel binding",
      "SQL parsing, statement/table level authorization or read-only enforcement",
      "connection pooling or multiplexing across clients",
      "replication protocol and logical decoding streams",
    ],
  },
  "database": {
    "role": role,
    "database": dbname,
    "password": "generated at runtime, never written to disk, logs or this report",
    "kept_after_run": keep_db == "1",
  },
  "checks": [],
}
for raw in checks:
    parts = raw.split("|", 2)
    out["checks"].append({"status": parts[0], "name": parts[1], "detail": parts[2] if len(parts) > 2 else ""})
failed = [c for c in out["checks"] if c["status"] != "PASS"]
out["summary"] = {"total": len(out["checks"]), "failed": len(failed)}
json.dump(out, open(out_path, "w"), indent=2, ensure_ascii=False)
print(f"checks={len(out['checks'])} failed={len(failed)}")
PY

if grep -q '"failed": 0' "$OUT_DIR/result.json"; then
  log "P4 acceptance PASSED"
else
  log "P4 acceptance has failures; see $OUT_DIR/result.json"
  exit 1
fi
