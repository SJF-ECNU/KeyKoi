#!/usr/bin/env bash
# P4 验收：Redis / MySQL / MongoDB 认证协议代理。
#
# 覆盖：客户端用 KeyKoi 会话令牌代替真实数据库密码，代理经 /v1/resolve 取真实凭据后
# 向上游完成认证，再转发命令。Redis 用本机 redis-server（独立端口 + requirepass）；
# MySQL / MongoDB 用 Docker 真实服务（临时端口、运行时随机口令、结束时删除）。
#
# 负例：错误令牌、无 runtime_delivery 许可、上游真实密码错误、客户端断开后上游会话释放。
# 口令与令牌都在运行时生成，不写入日志或报告；测试容器与临时库在结束时清理。
#   KEEP_ENV=1       保留测试容器与 redis-server（便于人工复核）
#   SKIP_DOCKER=1    只跑 Redis 部分
#   MYSQL_IMAGE / MYSQL80_IMAGE / MONGO_IMAGE  覆盖镜像（默认优先本机可用的 mirror.gcr.io）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/db-auth-proxies}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-dbauth.XXXXXX")"
BIN="$WORK/bin"
mkdir -p "$BIN" "$OUT_DIR"

MYSQL_IMAGE="${MYSQL_IMAGE:-mirror.gcr.io/library/mysql:8}"
MYSQL80_IMAGE="${MYSQL80_IMAGE:-mirror.gcr.io/library/mysql:8.0}"
MONGO_IMAGE="${MONGO_IMAGE:-mirror.gcr.io/library/mongo:7}"
KEEP_ENV="${KEEP_ENV:-0}"
SKIP_DOCKER="${SKIP_DOCKER:-0}"

CHECK_RESULTS=()
CONTAINERS=()
PROXY_PIDS=()

log() { printf '%s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

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

note() { # name detail（用于记录跳过原因，不计入检查）
  CHECK_RESULTS+=("SKIP|$1|$2")
  log "SKIP $1: $2"
}

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

cleanup() {
  set +e
  for pid in "${PROXY_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  [ -n "${REDIS_PID:-}" ] && kill "$REDIS_PID" 2>/dev/null
  if [ "$KEEP_ENV" != "1" ]; then
    for c in "${CONTAINERS[@]:-}"; do [ -n "$c" ] && docker rm -f "$c" >/dev/null 2>&1; done
  fi
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 环境与二进制
# ---------------------------------------------------------------------------
cd "$ROOT"
log "building binaries"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid

REDIS_SERVER="$(command -v redis-server || true)"
REDIS_CLI="$(command -v redis-cli || true)"
MONGO_SHELL="$(command -v mongosh || true)"
MYSQL_CLIENT="$(command -v mysql || true)"
if [ -z "$MYSQL_CLIENT" ] && [ -x /opt/homebrew/opt/mysql-client/bin/mysql ]; then
  MYSQL_CLIENT=/opt/homebrew/opt/mysql-client/bin/mysql
fi
if [ -z "$MYSQL_CLIENT" ] && [ -x /usr/local/opt/mysql-client/bin/mysql ]; then
  MYSQL_CLIENT=/usr/local/opt/mysql-client/bin/mysql
fi

DOCKER_OK=0
if [ "$SKIP_DOCKER" != "1" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  DOCKER_OK=1
fi

ensure_image() { # image -> 0 表示可用
  local image="$1"
  if docker image inspect "$image" >/dev/null 2>&1; then
    return 0
  fi
  log "pulling $image"
  docker pull "$image" >"$WORK/pull-$(echo "$image" | tr '/:' '__').log" 2>&1
}

wait_tcp() { # host port seconds
  python3 - "$1" "$2" "$3" <<'PY'
import socket, sys, time
host, port, limit = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
deadline = time.time() + limit
while time.time() < deadline:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit(1)
PY
}

# ---------------------------------------------------------------------------
# keykoid + 管理面
# ---------------------------------------------------------------------------
log "starting keykoid (temporary data dir, ephemeral ports)"
DATA="$WORK/data"
mkdir -p "$DATA"
export KEYKOI_DATA_DIR="$DATA"
"$BIN/keykoid" --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 \
  >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for _ in $(seq 1 100); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
"$BIN/keykoi" status >/dev/null 2>&1 || fail "keykoid did not start"
MASTER_PASSWORD="$(openssl rand -hex 16)"
printf '%s\n' "$MASTER_PASSWORD" | "$BIN/keykoi" init --password-stdin >/dev/null
unset MASTER_PASSWORD
PRINCIPAL="principal_local_$(id -u)"

add_credential() { # label protocol user password database
  local label="$1" protocol="$2" user="$3" password="$4" database="$5"
  local args=(--kind database --label "$label")
  [ -n "$user" ] && args+=(--field "username=$user")
  [ -n "$password" ] && args+=(--field "password=$password")
  [ -n "$database" ] && args+=(--field "database=$database")
  "$BIN/keykoi" --json credential add "${args[@]}"
}

add_binding() { # id credential origin route
  "$BIN/keykoi" --json binding add --id "$1" --credential "$2" --origin "$3" \
    --route "$4" --scheme basic --username-field username --password-field password >/dev/null
}

grant_runtime() { # binding
  "$BIN/keykoi" --json grant add --principal "$PRINCIPAL" --binding "$1" \
    --mode runtime_delivery --auth permanent --max-lease-seconds 600 >/dev/null
}

start_proxy() { # protocol binding prefix [proxy flags...] -> 设置 PROXY_PORT / PROXY_TOKEN
  local protocol="$1" binding="$2" prefix="$3"
  shift 3
  "$BIN/keykoi" db-proxy --protocol "$protocol" --binding "$binding" --listen 127.0.0.1:0 "$@" \
    >"$prefix.out" 2>"$prefix.err" &
  PROXY_PIDS+=($!)
  for _ in $(seq 1 100); do grep -q "session-token" "$prefix.out" 2>/dev/null && break; sleep 0.1; done
  grep -q "session-token" "$prefix.out" || fail "db-proxy ($protocol) did not print a session token"
  PROXY_PORT="$(grep -o 'listening 127\.0\.0\.1:[0-9]*' "$prefix.out" | head -1 | sed 's/.*://')"
  PROXY_TOKEN="$(grep -o 'kks_[A-Za-z0-9_-]*' "$prefix.out" | head -1)"
  [ -n "$PROXY_PORT" ] && [ -n "$PROXY_TOKEN" ] || fail "could not parse db-proxy startup output"
}

# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
REDIS_STATUS="skipped"
if [ -n "$REDIS_SERVER" ] && [ -n "$REDIS_CLI" ]; then
  log "== Redis: 本机 redis-server + requirepass"
  R_PORT="$(free_port)"
  R_PASSWORD="$(openssl rand -hex 16)"
  "$REDIS_SERVER" --port "$R_PORT" --requirepass "$R_PASSWORD" --save '' --appendonly no \
    --dir "$WORK" >"$WORK/redis.log" 2>&1 &
  REDIS_PID=$!
  REDIS_UP=0
  for _ in $(seq 1 100); do
    "$REDIS_CLI" -p "$R_PORT" -a "$R_PASSWORD" --no-auth-warning ping >/dev/null 2>&1 && { REDIS_UP=1; break; }
    sleep 0.1
  done
  if [ "$REDIS_UP" != "1" ]; then
    note "redis upstream" "redis-server did not become ready"
    REDIS_STATUS="skipped"
  else
    REDIS_VERSION="$("$REDIS_CLI" -p "$R_PORT" -a "$R_PASSWORD" --no-auth-warning INFO server | awk -F: '/redis_version/{print $2}' | tr -d '\r')"
    R_CRED="$(add_credential "p4 redis" redis default "$R_PASSWORD" "")"
    R_BIND="bind_p4_redis"
    R_BIND_NOGRANT="bind_p4_redis_nogrant"
    R_BIND_BADPW="bind_p4_redis_badpw"
    add_binding "$R_BIND" "$R_CRED" "http://127.0.0.1:$R_PORT" p4-redis
    add_binding "$R_BIND_NOGRANT" "$R_CRED" "http://127.0.0.1:$R_PORT" p4-redis-nogrant
    grant_runtime "$R_BIND"
    BAD_CRED="$(add_credential "p4 redis bad" redis default "wrong-upstream-password" "")"
    add_binding "$R_BIND_BADPW" "$BAD_CRED" "http://127.0.0.1:$R_PORT" p4-redis-badpw
    grant_runtime "$R_BIND_BADPW"

    start_proxy redis "$R_BIND" "$WORK/proxy-redis" --upstream-insecure
    R_PROXY_PORT="$PROXY_PORT"
    R_TOKEN="$PROXY_TOKEN"
    log "redis proxy on 127.0.0.1:$R_PROXY_PORT"

    R_SET="$("$REDIS_CLI" -h 127.0.0.1 -p "$R_PROXY_PORT" --no-auth-warning -a "$R_TOKEN" SET kk:smoke hello 2>&1 | tr -d '\r')"
    check "redis SET through proxy" "OK" "$R_SET"
    R_GET="$("$REDIS_CLI" -h 127.0.0.1 -p "$R_PROXY_PORT" --no-auth-warning -a "$R_TOKEN" GET kk:smoke 2>&1 | tr -d '\r')"
    check "redis GET through proxy" "hello" "$R_GET"
    R_PING="$("$REDIS_CLI" -h 127.0.0.1 -p "$R_PROXY_PORT" --no-auth-warning -a "$R_TOKEN" PING 2>&1 | tr -d '\r')"
    check "redis PING through proxy" "PONG" "$R_PING"
    R_SELECT="$("$REDIS_CLI" -h 127.0.0.1 -p "$R_PROXY_PORT" --no-auth-warning -a "$R_TOKEN" -n 3 SET kk:db3 v 2>&1 | tr -d '\r')"
    check "redis SELECT through proxy" "OK" "$R_SELECT"
    R_INFO="$("$REDIS_CLI" -h 127.0.0.1 -p "$R_PROXY_PORT" --no-auth-warning -a "$R_TOKEN" INFO server 2>&1 | tr -d '\r' | awk -F: '/redis_version/{print $2}')"
    check "redis INFO reaches the real upstream" "$REDIS_VERSION" "$R_INFO"

    set +e
    "$REDIS_CLI" -h 127.0.0.1 -p "$R_PROXY_PORT" --no-auth-warning -a kks_wrong_token PING \
      >"$WORK/redis-wrong.out" 2>&1
    R_WRONG_EXIT=$?
    set -e
    if [ "$R_WRONG_EXIT" -ne 0 ] && grep -q "not authorized" "$WORK/redis-wrong.out"; then
      check "redis wrong session token rejected" "denied" "denied"
    else
      check "redis wrong session token rejected" "denied" "exit=$R_WRONG_EXIT $(tail -1 "$WORK/redis-wrong.out")"
    fi

    start_proxy redis "$R_BIND_NOGRANT" "$WORK/proxy-redis-nogrant" --upstream-insecure
    set +e
    "$REDIS_CLI" -h 127.0.0.1 -p "$PROXY_PORT" --no-auth-warning -a "$PROXY_TOKEN" PING \
      >"$WORK/redis-nogrant.out" 2>&1
    R_NG_EXIT=$?
    set -e
    if [ "$R_NG_EXIT" -ne 0 ] && grep -q "not authorized" "$WORK/redis-nogrant.out"; then
      check "redis binding without runtime_delivery rejected" "denied" "denied"
    else
      check "redis binding without runtime_delivery rejected" "denied" "exit=$R_NG_EXIT $(tail -1 "$WORK/redis-nogrant.out")"
    fi

    start_proxy redis "$R_BIND_BADPW" "$WORK/proxy-redis-badpw" --upstream-insecure
    set +e
    "$REDIS_CLI" -h 127.0.0.1 -p "$PROXY_PORT" --no-auth-warning -a "$PROXY_TOKEN" PING \
      >"$WORK/redis-badpw.out" 2>&1
    R_BADPW_EXIT=$?
    set -e
    if [ "$R_BADPW_EXIT" -ne 0 ] && grep -q "upstream authentication failed" "$WORK/redis-badpw.out"; then
      check "redis wrong upstream password rejected" "denied" "denied"
    else
      check "redis wrong upstream password rejected" "denied" "exit=$R_BADPW_EXIT $(tail -1 "$WORK/redis-badpw.out")"
    fi

    # 客户端断开后上游会话必须释放。
    "$REDIS_CLI" -h 127.0.0.1 -p "$R_PROXY_PORT" --no-auth-warning -a "$R_TOKEN" PING >/dev/null 2>&1 || true
    # CLIENT LIST 自身也会占一条连接，所以只数“非 client 命令”的连接。
    R_CLIENTS="pending"
    for _ in $(seq 1 50); do
      R_CLIENTS="$("$REDIS_CLI" -p "$R_PORT" -a "$R_PASSWORD" --no-auth-warning CLIENT LIST 2>/dev/null | grep -v 'cmd=client' | grep -c 'id=' || true)"
      [ "$R_CLIENTS" = "0" ] && break
      sleep 0.1
    done
    check "redis upstream sessions released after client close" "0" "$R_CLIENTS"

    # 会话令牌只允许出现在代理启动时打印到 stdout 的那一行（供客户端取用），
    # 真实密码与令牌都不得出现在 keykoid 日志或代理 stderr 里。
    LEAKS=0
    for f in "$WORK/proxy-redis.out" "$WORK/proxy-redis.err" "$WORK/keykoid.log"; do
      grep -qF "$R_PASSWORD" "$f" 2>/dev/null && LEAKS=$((LEAKS + 1))
    done
    grep -qF "$R_TOKEN" "$WORK/keykoid.log" 2>/dev/null && LEAKS=$((LEAKS + 1))
    grep -qF "$R_TOKEN" "$WORK/proxy-redis.err" 2>/dev/null && LEAKS=$((LEAKS + 1))
    check "redis secrets absent from logs" "0" "$LEAKS"
    REDIS_STATUS="supported"
  fi
else
  note "redis upstream" "redis-server/redis-cli not installed"
fi

# ---------------------------------------------------------------------------
# MySQL
# ---------------------------------------------------------------------------
MYSQL_STATUS="skipped"
MYSQL_NATIVE_STATUS="not-run"
if [ "$DOCKER_OK" != "1" ] || [ -z "$MYSQL_CLIENT" ] || ! ensure_image "$MYSQL_IMAGE"; then
  note "mysql" "docker or mysql client unavailable (docker=$DOCKER_OK client=${MYSQL_CLIENT:-none})"
else
  MYSQL_VERSION="$("$MYSQL_CLIENT" --version | head -1)"
  C_NAME="keykoi-mysql-$(openssl rand -hex 3)"
  C_PORT="$(free_port)"
  ROOT_PW="$(openssl rand -hex 16)"
  UP_PW="$(openssl rand -hex 16)"
  docker run -d --name "$C_NAME" -e MYSQL_ROOT_PASSWORD="$ROOT_PW" \
    -p "127.0.0.1:$C_PORT:3306" "$MYSQL_IMAGE" >/dev/null
  CONTAINERS+=("$C_NAME")
  MYSQL_READY=0
  for _ in $(seq 1 120); do
    docker exec "$C_NAME" mysqladmin -h127.0.0.1 -uroot -p"$ROOT_PW" ping >/dev/null 2>&1 && { MYSQL_READY=1; break; }
    sleep 1
  done
  # 镜像会自动生成不受系统根信任、且没有 SAN 的上游证书：取出来做 CA 固定校验。
  MYSQL_TLS_ARGS=()
  if docker cp "$C_NAME:/var/lib/mysql/ca.pem" "$WORK/mysql-ca.pem" >/dev/null 2>&1; then
    MYSQL_TLS_ARGS=(--upstream-ca "$WORK/mysql-ca.pem" --mysql-upstream-tls-mode verify-ca)
  else
    note "mysql upstream TLS" "could not extract ca.pem; falling back to explicit plaintext opt-in"
    MYSQL_TLS_ARGS=(--upstream-insecure)
  fi
  if [ "$MYSQL_READY" != "1" ]; then
    note "mysql" "container did not become ready"
  else
    UP_VERSION="$(docker exec "$C_NAME" mysql -h127.0.0.1 -uroot -p"$ROOT_PW" -N -e 'select version()' 2>/dev/null)"
    docker exec "$C_NAME" mysql -h127.0.0.1 -uroot -p"$ROOT_PW" -e \
      "CREATE DATABASE IF NOT EXISTS keykoi_proxy_test; CREATE USER 'kkuser'@'%' IDENTIFIED WITH caching_sha2_password BY '$UP_PW'; GRANT ALL ON keykoi_proxy_test.* TO 'kkuser'@'%'; FLUSH PRIVILEGES;" \
      >/dev/null 2>&1
    AUTH_PLUGIN="$(docker exec "$C_NAME" mysql -h127.0.0.1 -uroot -p"$ROOT_PW" -N -e \
      "select plugin from mysql.user where user='kkuser'" 2>/dev/null)"
    check "mysql upstream user uses caching_sha2_password" "caching_sha2_password" "$AUTH_PLUGIN"

    M_CRED="$(add_credential "p4 mysql" mysql kkuser "$UP_PW" keykoi_proxy_test)"
    M_BIND="bind_p4_mysql"
    M_BIND_NOGRANT="bind_p4_mysql_nogrant"
    M_BIND_BADPW="bind_p4_mysql_badpw"
    BAD_M_CRED="$(add_credential "p4 mysql bad" mysql kkuser "wrong-upstream-password" keykoi_proxy_test)"
    add_binding "$M_BIND" "$M_CRED" "http://127.0.0.1:$C_PORT" p4-mysql
    add_binding "$M_BIND_NOGRANT" "$M_CRED" "http://127.0.0.1:$C_PORT" p4-mysql-nogrant
    add_binding "$M_BIND_BADPW" "$BAD_M_CRED" "http://127.0.0.1:$C_PORT" p4-mysql-badpw
    grant_runtime "$M_BIND"
    grant_runtime "$M_BIND_BADPW"

    start_proxy mysql "$M_BIND" "$WORK/proxy-mysql" "${MYSQL_TLS_ARGS[@]}"
    M_PROXY_PORT="$PROXY_PORT"
    M_TOKEN="$PROXY_TOKEN"
    mysql_run() { "$MYSQL_CLIENT" -h127.0.0.1 -P"$M_PROXY_PORT" -ukkuser "$@" 2>&1 | grep -v "Using a password"; }

    M_ONE="$(mysql_run -p"$M_TOKEN" -N -e 'select 1' | tr -d '\r' || true)"
    check "mysql select 1 through proxy (TLS, default ssl-mode)" "1" "$M_ONE"
    M_IDENT="$(mysql_run -p"$M_TOKEN" -N -e 'select current_user()' | tr -d '\r' || true)"
    check "mysql upstream identity is the registered user" "kkuser@%" "$M_IDENT"
    M_VERSION="$(mysql_run -p"$M_TOKEN" -N -e 'select @@version' | tr -d '\r' || true)"
    check "mysql proxied query reaches the real server" "$UP_VERSION" "$M_VERSION"
    M_PLAIN="$(mysql_run -p"$M_TOKEN" --ssl-mode=DISABLED --get-server-public-key -N -e 'select 2' | tr -d '\r' || true)"
    check "mysql plaintext client with RSA public key" "2" "$M_PLAIN"
    # 客户端侧 TLS 由客户端策略证明：--ssl-mode=REQUIRED 只在真正完成 TLS 握手后才可能成功；
    # 上游连接是明文，因此不能用上游的 Ssl_cipher 变量判断客户端这一跳。
    M_TLS_ONE="$(mysql_run -p"$M_TOKEN" --ssl-mode=REQUIRED -N -e 'select 5' | tr -d '\r' || true)"
    check "mysql client-side TLS enforced by --ssl-mode=REQUIRED" "5" "$M_TLS_ONE"
    TLS_LOGGED="$(grep -c 'tls=true' "$WORK/proxy-mysql.err" 2>/dev/null || true)"
    if [ "${TLS_LOGGED:-0}" -ge 1 ]; then
      check "mysql proxy log records a client-side TLS session" "yes" "yes"
    else
      check "mysql proxy log records a client-side TLS session" "yes" "no"
    fi

    set +e
    "$MYSQL_CLIENT" -h127.0.0.1 -P"$M_PROXY_PORT" -ukkuser -pkks_wrong_token -N -e 'select 1' \
      >"$WORK/mysql-wrong.out" 2>&1
    M_WRONG_EXIT=$?
    set -e
    if [ "$M_WRONG_EXIT" -ne 0 ] && grep -q "Access denied" "$WORK/mysql-wrong.out"; then
      check "mysql wrong session token rejected" "denied" "denied"
    else
      check "mysql wrong session token rejected" "denied" "exit=$M_WRONG_EXIT $(tail -1 "$WORK/mysql-wrong.out")"
    fi

    start_proxy mysql "$M_BIND_NOGRANT" "$WORK/proxy-mysql-nogrant" "${MYSQL_TLS_ARGS[@]}"
    set +e
    "$MYSQL_CLIENT" -h127.0.0.1 -P"$PROXY_PORT" -ukkuser -p"$PROXY_TOKEN" -N -e 'select 1' \
      >"$WORK/mysql-nogrant.out" 2>&1
    M_NG_EXIT=$?
    set -e
    if [ "$M_NG_EXIT" -ne 0 ] && grep -q "Access denied" "$WORK/mysql-nogrant.out"; then
      check "mysql binding without runtime_delivery rejected" "denied" "denied"
    else
      check "mysql binding without runtime_delivery rejected" "denied" "exit=$M_NG_EXIT $(tail -1 "$WORK/mysql-nogrant.out")"
    fi

    start_proxy mysql "$M_BIND_BADPW" "$WORK/proxy-mysql-badpw" "${MYSQL_TLS_ARGS[@]}"
    set +e
    "$MYSQL_CLIENT" -h127.0.0.1 -P"$PROXY_PORT" -ukkuser -p"$PROXY_TOKEN" -N -e 'select 1' \
      >"$WORK/mysql-badpw.out" 2>&1
    M_BADPW_EXIT=$?
    set -e
    if [ "$M_BADPW_EXIT" -ne 0 ] && grep -q "Access denied" "$WORK/mysql-badpw.out"; then
      check "mysql wrong upstream password rejected" "denied" "denied"
    else
      check "mysql wrong upstream password rejected" "denied" "exit=$M_BADPW_EXIT $(tail -1 "$WORK/mysql-badpw.out")"
    fi

    "$MYSQL_CLIENT" -h127.0.0.1 -P"$M_PROXY_PORT" -ukkuser -p"$M_TOKEN" -N -e 'select 3' >/dev/null 2>&1 || true
    M_LEFT="pending"
    for _ in $(seq 1 50); do
      M_LEFT="$(docker exec "$C_NAME" mysql -h127.0.0.1 -uroot -p"$ROOT_PW" -N -e \
        "select count(*) from information_schema.processlist where user='kkuser'" 2>/dev/null | tr -d '\r')"
      [ "$M_LEFT" = "0" ] && break
      sleep 0.1
    done
    check "mysql upstream sessions released after client close" "0" "$M_LEFT"

    LEAKS=0
    for f in "$WORK/proxy-mysql.out" "$WORK/proxy-mysql.err" "$WORK/keykoid.log"; do
      grep -qF "$UP_PW" "$f" 2>/dev/null && LEAKS=$((LEAKS + 1))
    done
    grep -qF "$M_TOKEN" "$WORK/keykoid.log" 2>/dev/null && LEAKS=$((LEAKS + 1))
    grep -qF "$M_TOKEN" "$WORK/proxy-mysql.err" 2>/dev/null && LEAKS=$((LEAKS + 1))
    check "mysql secrets absent from logs" "0" "$LEAKS"
    MYSQL_STATUS="supported"

    # 可选：真实 mysql:8.0 上的 mysql_native_password 上游认证。
    if ensure_image "$MYSQL80_IMAGE"; then
      N_NAME="keykoi-mysql80-$(openssl rand -hex 3)"
      N_PORT="$(free_port)"
      N_ROOT_PW="$(openssl rand -hex 16)"
      N_UP_PW="$(openssl rand -hex 16)"
      docker run -d --name "$N_NAME" -e MYSQL_ROOT_PASSWORD="$N_ROOT_PW" \
        -p "127.0.0.1:$N_PORT:3306" "$MYSQL80_IMAGE" >/dev/null
      CONTAINERS+=("$N_NAME")
      N_READY=0
      for _ in $(seq 1 120); do
        docker exec "$N_NAME" mysqladmin -h127.0.0.1 -uroot -p"$N_ROOT_PW" ping >/dev/null 2>&1 && { N_READY=1; break; }
        sleep 1
      done
      if [ "$N_READY" = "1" ] && docker exec "$N_NAME" mysql -h127.0.0.1 -uroot -p"$N_ROOT_PW" -e \
        "CREATE DATABASE keykoi_proxy_test; CREATE USER 'kknative'@'%' IDENTIFIED WITH mysql_native_password BY '$N_UP_PW'; GRANT ALL ON keykoi_proxy_test.* TO 'kknative'@'%';" \
        >/dev/null 2>&1; then
        N_CRED="$(add_credential "p4 mysql native" mysql kknative "$N_UP_PW" keykoi_proxy_test)"
        add_binding bind_p4_mysql_native "$N_CRED" "http://127.0.0.1:$N_PORT" p4-mysql-native
        grant_runtime bind_p4_mysql_native
        NATIVE_TLS_ARGS=()
        if docker cp "$N_NAME:/var/lib/mysql/ca.pem" "$WORK/mysql-native-ca.pem" >/dev/null 2>&1; then
          NATIVE_TLS_ARGS=(--upstream-ca "$WORK/mysql-native-ca.pem" --mysql-upstream-tls-mode verify-ca)
        else
          NATIVE_TLS_ARGS=(--upstream-insecure)
        fi
        start_proxy mysql bind_p4_mysql_native "$WORK/proxy-mysql-native" "${NATIVE_TLS_ARGS[@]}"
        N_ONE="$("$MYSQL_CLIENT" -h127.0.0.1 -P"$PROXY_PORT" -ukkuser -p"$PROXY_TOKEN" -N -e 'select 4' 2>&1 | grep -v "Using a password" | tr -d '\r' || true)"
        check "mysql upstream mysql_native_password authentication" "4" "$N_ONE"
        MYSQL_NATIVE_STATUS="supported"
        if [ "$KEEP_ENV" != "1" ]; then
          docker rm -f "$N_NAME" >/dev/null 2>&1
        fi
      else
        note "mysql native upstream" "mysql:8.0 image could not create a native-auth user"
      fi
    else
      note "mysql native upstream" "image $MYSQL80_IMAGE unavailable"
    fi
    if [ "$KEEP_ENV" != "1" ]; then
      docker rm -f "$C_NAME" >/dev/null 2>&1
    fi
  fi
fi

# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------
MONGO_STATUS="skipped"
if [ "$DOCKER_OK" != "1" ] || [ -z "$MONGO_SHELL" ] || ! ensure_image "$MONGO_IMAGE"; then
  note "mongo" "docker or mongosh unavailable (docker=$DOCKER_OK shell=${MONGO_SHELL:-none})"
else
  MG_NAME="keykoi-mongo-$(openssl rand -hex 3)"
  MG_PORT="$(free_port)"
  MG_ROOT_PW="$(openssl rand -hex 16)"
  MG_UP_PW="$(openssl rand -hex 16)"
  docker run -d --name "$MG_NAME" -e MONGO_INITDB_ROOT_USERNAME=root \
    -e MONGO_INITDB_ROOT_PASSWORD="$MG_ROOT_PW" -p "127.0.0.1:$MG_PORT:27017" "$MONGO_IMAGE" >/dev/null
  CONTAINERS+=("$MG_NAME")
  MG_READY=0
  for _ in $(seq 1 120); do
    docker exec "$MG_NAME" mongosh --quiet --eval 'db.runCommand({ping:1}).ok' admin \
      -u root -p "$MG_ROOT_PW" --authenticationDatabase admin 2>/dev/null | grep -q 1 && { MG_READY=1; break; }
    sleep 1
  done
  if [ "$MG_READY" != "1" ]; then
    note "mongo" "container did not become ready"
  else
    MG_VERSION="$(docker exec "$MG_NAME" mongosh --quiet --eval 'db.version()' admin \
      -u root -p "$MG_ROOT_PW" --authenticationDatabase admin 2>/dev/null | tr -d '\r')"
    docker exec "$MG_NAME" mongosh --quiet --eval \
      "db.getSiblingDB('admin').createUser({user:'kkuser',pwd:'$MG_UP_PW',roles:[{role:'root',db:'admin'}]})" \
      admin -u root -p "$MG_ROOT_PW" --authenticationDatabase admin >/dev/null 2>&1

    MG_CRED="$(add_credential "p4 mongo" mongo kkuser "$MG_UP_PW" admin)"
    MG_BIND="bind_p4_mongo"
    MG_BIND_NOGRANT="bind_p4_mongo_nogrant"
    MG_BIND_BADPW="bind_p4_mongo_badpw"
    BAD_MG_CRED="$(add_credential "p4 mongo bad" mongo kkuser "wrong-upstream-password" admin)"
    add_binding "$MG_BIND" "$MG_CRED" "http://127.0.0.1:$MG_PORT" p4-mongo
    add_binding "$MG_BIND_NOGRANT" "$MG_CRED" "http://127.0.0.1:$MG_PORT" p4-mongo-nogrant
    add_binding "$MG_BIND_BADPW" "$BAD_MG_CRED" "http://127.0.0.1:$MG_PORT" p4-mongo-badpw
    grant_runtime "$MG_BIND"
    grant_runtime "$MG_BIND_BADPW"

    start_proxy mongo "$MG_BIND" "$WORK/proxy-mongo"
    MG_PROXY_PORT="$PROXY_PORT"
    MG_TOKEN="$PROXY_TOKEN"
    mg_uri() { # token mechanism auth-source
      printf 'mongodb://kkuser:%s@127.0.0.1:%s/?authSource=%s&authMechanism=%s&directConnection=true' \
        "$1" "$MG_PROXY_PORT" "$3" "$2"
    }
    MG_PING="$(mongosh "$(mg_uri "$MG_TOKEN" PLAIN '%24external')" --quiet --eval \
      'print(db.runCommand({ping:1}).ok)' 2>&1 | tail -1 | tr -d '\r' || true)"
    check "mongo ping through proxy (SASL PLAIN)" "1" "$MG_PING"
    MG_VER="$(mongosh "$(mg_uri "$MG_TOKEN" PLAIN '%24external')" --quiet --eval \
      'print(db.version())' 2>&1 | tail -1 | tr -d '\r' || true)"
    check "mongo proxied command reaches the real server" "$MG_VERSION" "$MG_VER"
    MG_DOC="$(mongosh "$(mg_uri "$MG_TOKEN" PLAIN '%24external')" --quiet --eval \
      'const c=db.getSiblingDB("keykoi_proxy_test").items; c.insertOne({_id:"k1",v:42}); print(c.findOne({_id:"k1"}).v)' \
      2>&1 | tail -1 | tr -d '\r' || true)"
    check "mongo write/read through proxy" "42" "$MG_DOC"

    # 客户端断开后，代理必须关闭对应的上游认证会话。
    mongo_upstream_sessions() {
      docker exec "$MG_NAME" mongosh --quiet --eval \
        'print(db.getSiblingDB("admin").aggregate([{$currentOp:{allUsers:true,idleConnections:true,idleSessions:true}},{$match:{"effectiveUsers.user":"kkuser"}}]).toArray().length)' \
        admin -u root -p "$MG_ROOT_PW" --authenticationDatabase admin 2>/dev/null | tr -d '\r'
    }
    MG_LEFT="pending"
    for _ in $(seq 1 60); do
      MG_LEFT="$(mongo_upstream_sessions)"
      [ "$MG_LEFT" = "0" ] && break
      sleep 0.2
    done
    check "mongo upstream sessions released after client close" "0" "$MG_LEFT"

    set +e
    mongosh "$(mg_uri kks_wrong_token PLAIN '%24external')" --quiet --eval 'db.runCommand({ping:1})' \
      >"$WORK/mongo-wrong.out" 2>&1
    MG_WRONG_EXIT=$?
    set -e
    if [ "$MG_WRONG_EXIT" -ne 0 ] && grep -q "Authentication failed" "$WORK/mongo-wrong.out"; then
      check "mongo wrong session token rejected" "denied" "denied"
    else
      check "mongo wrong session token rejected" "denied" "exit=$MG_WRONG_EXIT $(tail -1 "$WORK/mongo-wrong.out")"
    fi

    # 客户端侧 SCRAM 必须明确拒绝，而不是假装成功（代理不掌握令牌原文，无法校验 proof）。
    set +e
    mongosh "$(mg_uri "$MG_TOKEN" SCRAM-SHA-256 admin)" --quiet --eval 'db.runCommand({ping:1})' \
      >"$WORK/mongo-scram.out" 2>&1
    MG_SCRAM_EXIT=$?
    set -e
    if [ "$MG_SCRAM_EXIT" -ne 0 ] && grep -q "SASL PLAIN" "$WORK/mongo-scram.out"; then
      check "mongo client-side SCRAM rejected with an explicit reason" "denied" "denied"
    else
      check "mongo client-side SCRAM rejected with an explicit reason" "denied" "exit=$MG_SCRAM_EXIT $(tail -1 "$WORK/mongo-scram.out")"
    fi

    start_proxy mongo "$MG_BIND_NOGRANT" "$WORK/proxy-mongo-nogrant"
    set +e
    mongosh "mongodb://kkuser:$PROXY_TOKEN@127.0.0.1:$PROXY_PORT/?authSource=%24external&authMechanism=PLAIN&directConnection=true" \
      --quiet --eval 'db.runCommand({ping:1})' >"$WORK/mongo-nogrant.out" 2>&1
    MG_NG_EXIT=$?
    set -e
    if [ "$MG_NG_EXIT" -ne 0 ] && grep -q "Authentication failed" "$WORK/mongo-nogrant.out"; then
      check "mongo binding without runtime_delivery rejected" "denied" "denied"
    else
      check "mongo binding without runtime_delivery rejected" "denied" "exit=$MG_NG_EXIT $(tail -1 "$WORK/mongo-nogrant.out")"
    fi

    start_proxy mongo "$MG_BIND_BADPW" "$WORK/proxy-mongo-badpw"
    set +e
    mongosh "mongodb://kkuser:$PROXY_TOKEN@127.0.0.1:$PROXY_PORT/?authSource=%24external&authMechanism=PLAIN&directConnection=true" \
      --quiet --eval 'db.runCommand({ping:1})' >"$WORK/mongo-badpw.out" 2>&1
    MG_BADPW_EXIT=$?
    set -e
    if [ "$MG_BADPW_EXIT" -ne 0 ] && grep -q "Authentication failed" "$WORK/mongo-badpw.out"; then
      check "mongo wrong upstream password rejected" "denied" "denied"
    else
      check "mongo wrong upstream password rejected" "denied" "exit=$MG_BADPW_EXIT $(tail -1 "$WORK/mongo-badpw.out")"
    fi

    LEAKS=0
    for f in "$WORK/proxy-mongo.out" "$WORK/proxy-mongo.err" "$WORK/keykoid.log"; do
      grep -qF "$MG_UP_PW" "$f" 2>/dev/null && LEAKS=$((LEAKS + 1))
    done
    grep -qF "$MG_TOKEN" "$WORK/keykoid.log" 2>/dev/null && LEAKS=$((LEAKS + 1))
    grep -qF "$MG_TOKEN" "$WORK/proxy-mongo.err" 2>/dev/null && LEAKS=$((LEAKS + 1))
    check "mongo secrets absent from logs" "0" "$LEAKS"
    MONGO_STATUS="supported"
    if [ "$KEEP_ENV" != "1" ]; then
      docker rm -f "$MG_NAME" >/dev/null 2>&1
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 清理与报告
# ---------------------------------------------------------------------------
if [ "$KEEP_ENV" != "1" ] && [ "${#CONTAINERS[@]}" -gt 0 ]; then
  REMAINING=0
  for c in "${CONTAINERS[@]}"; do
    docker inspect "$c" >/dev/null 2>&1 && REMAINING=$((REMAINING + 1))
  done
  check "temporary database containers removed" "0" "$REMAINING"
fi

log "writing result.json"
python3 - "$OUT_DIR/result.json" "$REDIS_STATUS" "$MYSQL_STATUS" "$MYSQL_NATIVE_STATUS" "$MONGO_STATUS" \
  "${REDIS_VERSION:-}" "${MYSQL_VERSION:-}" "${UP_VERSION:-}" "${MG_VERSION:-}" \
  "$KEEP_ENV" "${CHECK_RESULTS[@]}" <<'PY'
import json, sys

args = sys.argv[1:]
(out_path, redis_status, mysql_status, mysql_native_status, mongo_status,
 redis_version, mysql_client_version, mysql_upstream_version, mongo_upstream_version,
 keep_env) = args[:10]
checks = args[10:]

out = {
  "phase": "db-auth-proxies",
  "environment": {
    "redis_server": redis_version or "not available",
    "mysql_client": mysql_client_version or "not available",
    "mysql_upstream": mysql_upstream_version or "not available",
    "mysql_native_upstream": mysql_native_status,
    "mongo_upstream": mongo_upstream_version or "not available",
    "docker_images": "mirror.gcr.io/library/mysql:8 / mysql:8.0 / mongo:7 (override with MYSQL_IMAGE/MYSQL80_IMAGE/MONGO_IMAGE)",
    "kept_after_run": keep_env == "1",
  },
  "protocols": {
    "redis": {
      "status": redis_status,
      "client_auth": "AUTH <session-token> / AUTH <user> <session-token>, terminated by the proxy",
      "upstream_auth": ["AUTH password (requirepass)", "AUTH user password (Redis 6+ ACL)"],
      "forwarding": "RESP2/RESP3 messages forwarded verbatim; re-AUTH rewrites the password slot to the real secret",
      "unsupported": ["client-side and upstream TLS", "cluster redirection routing"],
    },
    "mysql": {
      "status": mysql_status,
      "client_auth": "caching_sha2_password full authentication; session token arrives over client-side TLS or RSA-encrypted",
      "upstream_auth": ["mysql_native_password", "caching_sha2_password (fast path + full auth via RSA public key)"],
      "forwarding": "binary relay after authentication; result sets, ERR and COM_QUIT untouched",
      "unsupported": ["upstream TLS", "COM_CHANGE_USER re-authentication", "result-set rewriting"],
    },
    "mongo": {
      "status": mongo_status,
      "client_auth": "SASL PLAIN (mongosh --authenticationMechanism PLAIN, authSource=$external)",
      "upstream_auth": ["SCRAM-SHA-256 (full client implementation with server signature verification)"],
      "forwarding": "OP_MSG relay after authentication; legacy OP_QUERY handshake answered with OP_REPLY",
      "unsupported": [
        "client-side SCRAM-SHA-256/SCRAM-SHA-1 termination: the proxy does not hold the token "
        "plaintext, so it cannot verify the client proof; faking it would accept any password, "
        "so SCRAM is rejected explicitly instead",
        "OP_COMPRESSED, client TLS, X.509 client certificates",
      ],
      "not_implemented": ["client-side SCRAM-SHA-256"],
    },
  },
  "checks": [],
}
for raw in checks:
    parts = raw.split("|", 2)
    item = {"status": parts[0], "name": parts[1], "detail": parts[2] if len(parts) > 2 else ""}
    if parts[0] == "SKIP":
        item["status"] = "SKIP"
    out["checks"].append(item)
failed = [c for c in out["checks"] if c["status"] == "FAIL"]
skipped = [c for c in out["checks"] if c["status"] == "SKIP"]
out["summary"] = {
    "total": len(out["checks"]),
    "failed": len(failed),
    "skipped": len(skipped),
    "passed": len([c for c in out["checks"] if c["status"] == "PASS"]),
}
json.dump(out, open(out_path, "w"), indent=2, ensure_ascii=False)
print(f"checks={len(out['checks'])} failed={len(failed)} skipped={len(skipped)}")
PY

if grep -q '"failed": 0' "$OUT_DIR/result.json"; then
  log "db-auth-proxies acceptance PASSED"
else
  log "db-auth-proxies acceptance has failures; see $OUT_DIR/result.json"
  exit 1
fi
