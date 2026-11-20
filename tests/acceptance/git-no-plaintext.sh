#!/usr/bin/env bash
# Git 不明文验收：git 只拿中介令牌，真实仓库凭据由网关注入。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/git-no-plaintext}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-git.XXXXXX")"
BIN="$WORK/bin"; DATA="$WORK/data"; HOME_DIR="$WORK/home"
mkdir -p "$BIN" "$DATA" "$HOME_DIR/repos" "$OUT_DIR"
log() { printf '%s\n' "$*" >&2; }

cleanup() {
  set +e
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  [ -n "${GIT_PID:-}" ] && kill "$GIT_PID" 2>/dev/null
  wait 2>/dev/null
  if [ "${KEEP_WORK:-0}" = "1" ]; then echo "work dir kept: $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

cd "$ROOT"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid
go build -o "$BIN/githttp" ./tests/fixtures/githttp

export KEYKOI_DATA_DIR="$DATA" KEYKOI_SOCKET="$DATA/keykoid.sock" HOME="$HOME_DIR"
export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1

GIT_USER="alice"; GIT_PASS="$(openssl rand -hex 12)"
BASIC="Basic $(printf '%s:%s' "$GIT_USER" "$GIT_PASS" | base64)"

log "prepare a real bare repository and controlled git smart HTTP server"
git init -q --bare "$HOME_DIR/repos/repo.git"
git clone -q "$HOME_DIR/repos/repo.git" "$WORK/seed" 2>/dev/null
( cd "$WORK/seed" && printf 'hello-keykoi\n' > README.md && git add README.md \
  && git -c user.email=fixture@example.com -c user.name=fixture commit -qm init \
  && git push -q origin HEAD:main )
git --git-dir "$HOME_DIR/repos/repo.git" symbolic-ref HEAD refs/heads/main
"$BIN/githttp" --addr 127.0.0.1:0 --root "$HOME_DIR/repos" --expect-basic "$BASIC" \
  --addr-file "$WORK/git.addr" >"$WORK/githttp.log" 2>&1 &
GIT_PID=$!
for i in $(seq 1 60); do [ -s "$WORK/git.addr" ] && break; sleep 0.1; done
UP="http://$(cat "$WORK/git.addr")"

log "keykoid + binding for the repository"
"$BIN/keykoid" --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for i in $(seq 1 80); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
printf 'git-acceptance-password\n' | "$BIN/keykoi" init --password-stdin >/dev/null
GW="$("$BIN/keykoi" --json status | python3 -c 'import json,sys;print(json.load(sys.stdin)["gateway"])')"
PRINCIPAL="principal_local_$(id -u)"
CRED="$("$BIN/keykoi" --json credential add --kind database --label "git repo basic" \
  --field "username=$GIT_USER" --field "password=$GIT_PASS" | tr -d '\n')"
"$BIN/keykoi" --json binding add --id bind_git --credential "$CRED" --origin "$UP" --route git --scheme basic >/dev/null
"$BIN/keykoi" --json grant add --principal "$PRINCIPAL" --binding bind_git --mode proxy --max-lease-seconds 300 --auth permanent >/dev/null

CHECKS=()
check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then CHECKS+=("PASS|$name|$actual"); log "PASS $name"
  else CHECKS+=("FAIL|$name|expected=$expected actual=$actual"); log "FAIL $name expected=$expected actual=$actual"; fi
}

log "configure git to use the KeyKoi gateway"
"$BIN/keykoi" git setup --host git.example --binding bind_git --route git --gateway "$GW" \
  --keykoi-bin "$BIN/keykoi" --file "$HOME_DIR/.gitconfig" >"$WORK/setup.out"
check "helper entry contains no real password" "0" "$(grep -c "$GIT_PASS" "$HOME_DIR/.gitconfig" || true)"
check "helper mints only an intermediary token" "kks_" "$("$BIN/keykoi" helper git-token --binding bind_git | sed -n 's/^password=\(kks_.*\)$/\1/p' | cut -c1-4)"
check "helper output has no real password" "0" "$("$BIN/keykoi" helper git-token --binding bind_git | grep -c "$GIT_PASS" || true)"

log "real git clone through the gateway"
set +e
git -c protocol.version=2 clone "https://git.example/repo.git" "$WORK/clone" >"$WORK/clone.out" 2>"$WORK/clone.err"
CLONE_EXIT=$?
set -e
check "git clone succeeds" "0" "$CLONE_EXIT"
check "cloned content is correct" "hello-keykoi" "$(cat "$WORK/clone/README.md" 2>/dev/null | tr -d '\n')"

STATS="$(curl -sS "$UP/stats")"
stat() { printf '%s' "$STATS" | python3 -c "import json,sys;print(json.load(sys.stdin)[\"$1\"])"; }
check "clone traffic reached the repository" "1" "$(python3 -c "print(1 if $(stat requests) > 0 else 0)")"
check "repository never saw the intermediary token" "0" "$(stat kks_seen)"
check "git supplied credentials without an unauthenticated retry" "0" "$(stat denied)"

log "teardown restores plain git behavior"
"$BIN/keykoi" git teardown --host git.example --route git --gateway "$GW" --file "$HOME_DIR/.gitconfig" >/dev/null
set +e
git clone "https://git.example/repo.git" "$WORK/clone2" >/dev/null 2>"$WORK/clone2.err"
CLONE2_EXIT=$?
set -e
check "clone without the rewrite cannot reach the fixture" "1" "$(python3 -c "print(0 if $CLONE2_EXIT==0 else 1)")"

check "git credential store was never created" "1" "$(test ! -e "$HOME_DIR/.git-credentials" && echo 1 || echo 0)"

GIT_VERSION="$(git --version)"
python3 - "$OUT_DIR/result.json" "$GIT_VERSION" "${CHECKS[@]}" <<'PY'
import json, sys
out = {"phase": "git-no-plaintext", "environment": {"os": "macOS 27.0 arm64", "git": sys.argv[2]}, "checks": []}
for raw in sys.argv[3:]:
    st, name, detail = raw.split("|", 2)
    out["checks"].append({"status": st, "name": name, "detail": detail})
out["summary"] = {"total": len(out["checks"]), "failed": sum(1 for c in out["checks"] if c["status"] != "PASS")}
json.dump(out, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
print(f"checks={out['summary']['total']} failed={out['summary']['failed']}")
PY
grep -q '"failed": 0' "$OUT_DIR/result.json" || { log "git acceptance FAILED"; exit 1; }
log "git acceptance PASSED"
