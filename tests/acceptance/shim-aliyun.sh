#!/usr/bin/env bash
# 无感入口验收：安装 shim 后直接执行 aliyun，由 KeyKoi 注入凭证。
# 使用受控 HTTPS 上游与本机自签证书；不访问真实阿里云端点。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/shim-aliyun}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-shim.XXXXXX")"
BIN="$WORK/bin"; DATA="$WORK/data"; HOME_DIR="$WORK/home"
SHIM_DIR="$DATA/shims"
mkdir -p "$BIN" "$DATA" "$HOME_DIR" "$OUT_DIR"
log() { printf '%s\n' "$*" >&2; }

cleanup() {
  set +e
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  [ -n "${UP_PID:-}" ] && kill "$UP_PID" 2>/dev/null
  [ -n "${UP2_PID:-}" ] && kill "$UP2_PID" 2>/dev/null
  wait 2>/dev/null
  if [ "${KEEP_WORK:-0}" = "1" ]; then echo "work dir kept: $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

command -v aliyun >/dev/null || { log "aliyun CLI is not installed"; exit 2; }

cd "$ROOT"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/mockupstream" ./tests/fixtures/mockupstream

export KEYKOI_DATA_DIR="$DATA" KEYKOI_SOCKET="$DATA/keykoid.sock" HOME="$HOME_DIR"

AK="AKID$(openssl rand -hex 8 | tr 'a-f' 'A-F')"
SK="$(openssl rand -hex 20)"
STOK="$(openssl rand -hex 12)"
UP_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"

log "controlled HTTPS upstream"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" >/dev/null 2>&1
"$BIN/mockupstream" --addr "127.0.0.1:$UP_PORT" --expect-query "AccessKeyId=$AK" \
  --tls-cert "$WORK/cert.pem" --tls-key "$WORK/key.pem" >"$WORK/up.log" 2>&1 &
UP_PID=$!
for i in $(seq 1 50); do curl -fsS --cacert "$WORK/cert.pem" "https://127.0.0.1:$UP_PORT/stats" >/dev/null 2>&1 && break; sleep 0.1; done

log "keykoid + seed"
"$BIN/keykoid" --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for i in $(seq 1 80); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
printf 'shim-acceptance-password\n' | "$BIN/keykoi" init --password-stdin >/dev/null

PRINCIPAL="principal_local_$(id -u)"
CRED="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "aliyun shim account" \
  --field "access_id=$AK" --field "access_secret=$SK" --field "session_token=$STOK")"
"$BIN/keykoi" --json binding add --id bind_aliyun --credential "$CRED" --origin "https://127.0.0.1:$UP_PORT" --route aliyun-ecs --scheme bearer >/dev/null
"$BIN/keykoi" --json grant add --principal "$PRINCIPAL" --binding bind_aliyun --mode runtime_delivery --auth permanent --max-lease-seconds 300 >/dev/null

# 第二个凭据没有临时令牌，用于验证纯静态 AK/SK 路径。
AK2="AKID$(openssl rand -hex 8 | tr 'a-f' 'A-F')"
SK2="$(openssl rand -hex 20)"
UP2_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
"$BIN/mockupstream" --addr "127.0.0.1:$UP2_PORT" --expect-query "AccessKeyId=$AK2" \
  --tls-cert "$WORK/cert.pem" --tls-key "$WORK/key.pem" >"$WORK/up2.log" 2>&1 &
UP2_PID=$!
for i in $(seq 1 50); do curl -fsS --cacert "$WORK/cert.pem" "https://127.0.0.1:$UP2_PORT/stats" >/dev/null 2>&1 && break; sleep 0.1; done
CRED2="$("$BIN/keykoi" --json credential add --kind access_key_pair --label "aliyun static account" \
  --field "access_id=$AK2" --field "access_secret=$SK2")"
"$BIN/keykoi" --json binding add --id bind_aliyun_static --credential "$CRED2" --origin "https://127.0.0.1:$UP2_PORT" --route aliyun-static --scheme bearer >/dev/null
"$BIN/keykoi" --json grant add --principal "$PRINCIPAL" --binding bind_aliyun_static --mode runtime_delivery --auth permanent --max-lease-seconds 300 >/dev/null

# 预先存在的用户明文配置：必须被 shim 隔离而不是被使用。
mkdir -p "$HOME_DIR/.aliyun"
USER_AK="AKIDUSERCFG0000000000"
cat > "$HOME_DIR/.aliyun/config.json" <<JSON
{"current":"default","profiles":[{"name":"default","mode":"AK","access_key_id":"$USER_AK","access_key_secret":"userconfigsecret","region_id":"cn-beijing"}],"meta_path":"","plugins":[],"scopes":[]}
JSON

CHECKS=()
check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then CHECKS+=("PASS|$name|$actual"); log "PASS $name"
  else CHECKS+=("FAIL|$name|expected=$expected actual=$actual"); log "FAIL $name expected=$expected actual=$actual"; fi
}

log "install shim with PATH integration and config isolation"
"$BIN/keykoi" --json shim install --name aliyun --exe "$(command -v aliyun)" --binding bind_aliyun \
  --env ALIBABA_CLOUD_ACCESS_KEY_ID=field:access_id \
  --env ALIBABA_CLOUD_ACCESS_KEY_SECRET=field:access_secret \
  --env ALIBABA_CLOUD_SECURITY_TOKEN=field:session_token \
  --prepend-arg=--config-path --prepend-arg="$SHIM_DIR/aliyun.no-config.json" \
  --update-shell >"$WORK/install.out" 2>"$WORK/install.err"
check "install warns about the existing plaintext profile" "yes" "$(grep -qi '仍保存明文访问密钥' "$WORK/install.err" && echo yes || echo no)"

check "shim symlink installed" "1" "$(test -L "$SHIM_DIR/aliyun" && echo 1 || echo 0)"
check "shim record has no secret" "0" "$(grep -c "$SK" "$SHIM_DIR/aliyun.json" || true)"
check "shell path block added once" "1" "$(grep -c '# >>> keykoi shim >>>' "$HOME_DIR/.zshrc" | tr -d ' ')"
RESOLVED="$(bash -c "source '$HOME_DIR/.zshrc'; command -v aliyun")"
check "PATH now resolves aliyun to the shim" "yes" "$(python3 -c "import os;print('yes' if os.path.realpath('$RESOLVED')==os.path.realpath('$SHIM_DIR/aliyun') else 'no')")"

log "run aliyun directly (no keykoi prefix)"
set +e
bash -c "source '$HOME_DIR/.zshrc'; aliyun ecs DescribeRegions --endpoint 127.0.0.1:$UP_PORT --region cn-hangzhou --skip-secure-verify" \
  >"$WORK/direct.out" 2>"$WORK/direct.err"
DIRECT_EXIT=$?
set -e
check "aliyun via shim exits 0" "0" "$DIRECT_EXIT"
check "response came back through the shim" "yes" "$(grep -q DescribeRegionsResponse "$WORK/direct.out" && echo yes || echo no)"

STATS="$(curl -sS --cacert "$WORK/cert.pem" "https://127.0.0.1:$UP_PORT/stats")"
stat() { printf '%s' "$STATS" | python3 -c "import json,sys;print(json.load(sys.stdin)[\"$1\"])"; }
check "upstream saw the injected AccessKeyId" "1" "$(stat query_matched)"
check "user's plaintext config was bypassed, not used" "0" "$(printf '%s' "$STATS" | grep -c 'AKIDUSERCFG' | tr -d ' ')"
check "user's config file itself was not modified" "yes" "$(grep -q "$USER_AK" "$HOME_DIR/.aliyun/config.json" && echo yes || echo no)"
check "managed config path stays absent (no plaintext file created)" "1" "$(test ! -e "$SHIM_DIR/aliyun.no-config.json" && echo 1 || echo 0)"
check "aliyun signed with the injected secret" "True" "$(stat signature_seen)"
check "security token delivered" "True" "$(stat security_token_seen)"
check "no intermediary token upstream" "0" "$(stat session_tokens)"

log "arguments are preserved byte-for-byte"
bash -c "source '$HOME_DIR/.zshrc'; aliyun ecs DescribeRegions --endpoint 127.0.0.1:$UP_PORT --region cn-shanghai --skip-secure-verify" >/dev/null 2>&1 || true
STATS2="$(curl -sS --cacert "$WORK/cert.pem" "https://127.0.0.1:$UP_PORT/stats")"
check "region argument reached the upstream request" "1" "$(printf '%s' "$STATS2" | grep -c 'RegionId=cn-shanghai' | tr -d ' ')"

log "static AK/SK (no session token) works through a second shim"
"$BIN/keykoi" --json shim install --name aliyun-static --exe "$(command -v aliyun)" --binding bind_aliyun_static \
  --env ALIBABA_CLOUD_ACCESS_KEY_ID=field:access_id \
  --env ALIBABA_CLOUD_ACCESS_KEY_SECRET=field:access_secret \
  --prepend-arg=--config-path --prepend-arg="$SHIM_DIR/aliyun-static.no-config.json" >/dev/null
bash -c "source '$HOME_DIR/.zshrc'; aliyun-static ecs DescribeRegions --endpoint 127.0.0.1:$UP2_PORT --region cn-hangzhou --skip-secure-verify" >"$WORK/static.out" 2>&1 || true
STATS2="$(curl -sS --cacert "$WORK/cert.pem" "https://127.0.0.1:$UP2_PORT/stats")"
check "static credential works without a security token" "1" "$(printf '%s' "$STATS2" | python3 -c 'import json,sys;print(json.load(sys.stdin)["query_matched"])')"
check "static call sent no empty security token" "False" "$(printf '%s' "$STATS2" | python3 -c 'import json,sys;print(json.load(sys.stdin)["security_token_seen"])')"

log "user-supplied --config-path is refused instead of silently bypassing KeyKoi"
set +e
bash -c "source '$HOME_DIR/.zshrc'; aliyun --config-path '$HOME_DIR/.aliyun/config.json' ecs DescribeRegions --region cn-hangzhou" >"$WORK/conflict.out" 2>"$WORK/conflict.err"
CONFLICT_EXIT=$?
set -e
check "explicit config path is refused" "1" "$(python3 -c "print(0 if $CONFLICT_EXIT==0 else 1)")"
check "refusal explains the shim limitation" "yes" "$(grep -qi 'not supported through the shim' "$WORK/conflict.err" && echo yes || echo no)"

log "configure commands stay native (no credential injection)"
bash -c "source '$HOME_DIR/.zshrc'; aliyun configure list" >"$WORK/configure.out" 2>&1 || true
check "configure list still reads the real (masked) profile" "yes" "$(grep -q 'default' "$WORK/configure.out" && grep -q 'cn-beijing' "$WORK/configure.out" && echo yes || echo no)"

log "exit codes propagate"
set +e
bash -c "source '$HOME_DIR/.zshrc'; aliyun nonexistent-command" >/dev/null 2>&1
BAD_EXIT=$?
set -e
check "invalid subcommand exits non-zero through shim" "1" "$(python3 -c "print(1 if $BAD_EXIT != 0 else 0)")"

log "recursion guard"
set +e
"$BIN/keykoi" shim install --name aliyun-self --exe "$SHIM_DIR/aliyun" --binding bind_aliyun --skip-check >"$WORK/self.out" 2>&1
SELF_EXIT=$?
set -e
check "refuses to shim a binary that resolves to itself" "1" "$(python3 -c "print(0 if $SELF_EXIT==0 else 1)")"

log "daemon unavailable: local commands still work, credential calls fail clearly"
kill "$KEYKOID_PID" 2>/dev/null || true
wait "$KEYKOID_PID" 2>/dev/null || true
set +e
bash -c "source '$HOME_DIR/.zshrc'; aliyun version" >"$WORK/ver.out" 2>&1
VER_EXIT=$?
bash -c "source '$HOME_DIR/.zshrc'; aliyun ecs DescribeRegions --region cn-hangzhou" >"$WORK/down.out" 2>"$WORK/down.err"
DOWN_EXIT=$?
set -e
check "local commands work offline (no credential needed)" "0" "$VER_EXIT"
check "credential calls fail when keykoid is down" "1" "$(python3 -c "print(0 if $DOWN_EXIT==0 else 1)")"
check "failure names the daemon problem" "yes" "$(grep -qi 'keykoid\|alias aliyun' "$WORK/down.err" && echo yes || echo no)"

log "remove shim restores the original command resolution"
"$BIN/keykoi" shim remove --name aliyun --update-shell >/dev/null
check "shim symlink removed" "1" "$(test ! -e "$SHIM_DIR/aliyun" && echo 1 || echo 0)"
check "PATH block removed from shell rc" "0" "$(grep -c '# >>> keykoi shim >>>' "$HOME_DIR/.zshrc" || true)"
check "aliyun resolves to the real tool again" "$(command -v aliyun)" "$(bash -c "source '$HOME_DIR/.zshrc'; command -v aliyun")"

python3 - "$OUT_DIR/result.json" "$(aliyun version 2>&1 | head -1)" "${CHECKS[@]}" <<'PY'
import json, sys
out = {
  "phase": "shim-aliyun",
  "environment": {
    "os": "macOS 27.0 arm64",
    "tool": sys.argv[2],
    "entry": "PATH shim -> keykoi runtime_delivery",
    "upstream": "controlled HTTPS mock (self-signed test cert)",
    "caveat": "aliyun CLI --skip-secure-verify only for the controlled test certificate.",
  },
  "checks": [],
}
for raw in sys.argv[3:]:
    st, name, detail = raw.split("|", 2)
    out["checks"].append({"status": st, "name": name, "detail": detail})
out["summary"] = {"total": len(out["checks"]), "failed": sum(1 for c in out["checks"] if c["status"] != "PASS")}
json.dump(out, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
print(f"checks={out['summary']['total']} failed={out['summary']['failed']}")
PY
grep -q '"failed": 0' "$OUT_DIR/result.json" || { log "shim acceptance FAILED"; exit 1; }
log "shim acceptance PASSED"
