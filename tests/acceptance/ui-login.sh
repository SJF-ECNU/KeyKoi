#!/usr/bin/env bash
# `keykoi ui` 一键登录看板验收。
#
# 覆盖：默认从后台取管理地址、--admin 覆盖、--no-open 打印带令牌的登录链接、
# 默认模式不把令牌写到标准输出、管理页面能取到 hash 登录逻辑、以及用 node
# 无头执行页面里的 hash 解析/清除函数（返回令牌、清除 hash、无令牌时不动 hash）。
#
# 脚本在临时目录里起 keykoid、初始化密钥库，不触碰真实数据目录与浏览器。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/ui-login}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-ui-login.XXXXXX")"
BIN="$WORK/bin"; DATA="$WORK/data"; HOME_DIR="$WORK/home"; SHIM="$WORK/shim"
mkdir -p "$BIN" "$DATA" "$HOME_DIR" "$SHIM" "$OUT_DIR"
log() { printf '%s\n' "$*" >&2; }

cleanup() {
  set +e
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  wait 2>/dev/null
  if [ "${KEEP_WORK:-0}" = "1" ]; then echo "work dir kept: $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

cd "$ROOT"
# 验收使用独立 HOME，但 Go 工具链必须继续用真实模块缓存。
REAL_HOME="$HOME"
GOENV=(env HOME="$REAL_HOME")
"${GOENV[@]}" go build -o "$BIN/keykoi" ./cmd/keykoi
"${GOENV[@]}" go build -o "$BIN/keykoid" ./cmd/keykoid

CHECKS=()
check() { # name expected actual
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    CHECKS+=("PASS|$name|$actual"); log "PASS $name"
  else
    CHECKS+=("FAIL|$name|expected=$expected actual=$actual"); log "FAIL $name expected=$expected actual=$actual"
  fi
}
contains() { # name needle haystack
  local name="$1" needle="$2" hay="$3"
  if printf '%s' "$hay" | grep -qF -- "$needle"; then
    CHECKS+=("PASS|$name|contains '$needle'"); log "PASS $name"
  else
    CHECKS+=("FAIL|$name|missing '$needle'"); log "FAIL $name missing '$needle'"
  fi
}
absent() { # name needle haystack
  local name="$1" needle="$2" hay="$3"
  if printf '%s' "$hay" | grep -qF -- "$needle"; then
    CHECKS+=("FAIL|$name|unexpected '$needle' present"); log "FAIL $name unexpected '$needle'"
  else
    CHECKS+=("PASS|$name|does not contain '$needle'"); log "PASS $name"
  fi
}

export KEYKOI_DATA_DIR="$DATA" KEYKOI_SOCKET="$DATA/keykoid.sock" HOME="$HOME_DIR"
export NO_PROXY="127.0.0.1,localhost,::1" no_proxy="127.0.0.1,localhost,::1"
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true
PASSWORD="ui-login-acceptance-password"

log "start keykoid on ephemeral ports"
"$BIN/keykoid" --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for i in $(seq 1 100); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
printf '%s\n' "$PASSWORD" | "$BIN/keykoi" init --password-stdin >/dev/null
TOKEN="$(cat "$DATA/admin.token")"
ADMIN="$("$BIN/keykoi" --json status | python3 -c 'import json,sys;print(json.load(sys.stdin)["admin"])')"
ADMIN_PORT="${ADMIN##*:}"
log "admin address: $ADMIN"

log "== --no-open：默认取后台管理地址并打印登录链接 =="
set +e
UI_OUT="$("$BIN/keykoi" ui --no-open 2>"$WORK/ui.err")"; UI_CODE=$?
set -e
UI_ERR="$(cat "$WORK/ui.err")"
check "--no-open exits 0" "0" "$UI_CODE"
contains "prints the admin URL with the token fragment" "http://$ADMIN/#token=$TOKEN" "$UI_OUT"
contains "explains the fragment is cleared by the page" "fragment" "$UI_OUT"
absent "stderr carries no token" "$TOKEN" "$UI_ERR"
check "token appears only on the URL line" "" "$(printf '%s\n' "$UI_OUT" | grep -v 'http' | grep -F -- "$TOKEN" || true)"

log "== --admin 覆盖与地址规范化 =="
UI2_OUT="$("$BIN/keykoi" ui --no-open --admin "$ADMIN")"
check "explicit --admin produces the same link" "http://$ADMIN/#token=$TOKEN" "$(printf '%s\n' "$UI2_OUT" | grep -F 'http' | tr -d ' ')"
UI3_OUT="$("$BIN/keykoi" ui --no-open --admin "http://$ADMIN/")"
check "scheme and trailing slash are normalized" "http://$ADMIN/#token=$TOKEN" "$(printf '%s\n' "$UI3_OUT" | grep -F 'http' | tr -d ' ')"

log "== 默认模式：交给系统浏览器，且不打印令牌 =="
cat >"$SHIM/open" <<'SHIMEOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$KEYKOI_OPEN_LOG"
SHIMEOF
chmod 755 "$SHIM/open"
export KEYKOI_OPEN_LOG="$WORK/open.log"
set +e
OPEN_OUT="$(PATH="$SHIM:$PATH" "$BIN/keykoi" ui --admin "$ADMIN" 2>"$WORK/ui-open.err")"; OPEN_CODE=$?
set -e
OPEN_ERR="$(cat "$WORK/ui-open.err")"
OPEN_URL="$(cat "$KEYKOI_OPEN_LOG" 2>/dev/null || true)"
check "browser mode exits 0" "0" "$OPEN_CODE"
check "the browser receives the tokenized link" "http://$ADMIN/#token=$TOKEN" "$OPEN_URL"
contains "browser mode reports the opened address" "已在本机浏览器打开 http://$ADMIN/" "$OPEN_OUT"
absent "browser mode keeps the token out of stdout" "$TOKEN" "$OPEN_OUT"
absent "browser mode keeps the token out of stderr" "$TOKEN" "$OPEN_ERR"
unset KEYKOI_OPEN_LOG

log "== 失败路径：没有令牌或后台未运行时明确报错 =="
mkdir -p "$WORK/empty"
set +e
FAIL_OUT="$("$BIN/keykoi" ui --no-open --data-dir "$WORK/empty" --socket "$WORK/empty/none.sock" 2>"$WORK/ui-fail.err")"; FAIL_CODE=$?
set -e
FAIL_ERR="$(cat "$WORK/ui-fail.err")"
check "missing backend exits non-zero" "1" "$FAIL_CODE"
contains "missing backend explains what to do" "读取后台管理地址失败" "$FAIL_ERR"
absent "failure path prints no token" "$TOKEN" "$FAIL_OUT$FAIL_ERR"

log "== 管理页面：hash 登录逻辑存在 =="
PAGE="$WORK/index.html"
curl -sS -D "$WORK/page.headers" "http://$ADMIN/" -o "$PAGE"
contains "page is served" "<!doctype html>" "$(head -1 "$PAGE")"
contains "page reads location.hash" "location.hash" "$(cat "$PAGE")"
contains "page parses the token parameter" "params.get(\"token\")" "$(cat "$PAGE")"
contains "page clears the hash" "history.replaceState" "$(cat "$PAGE")"
contains "page fills the token box and connects" "loginFromHash" "$(cat "$PAGE")"
contains "page keeps Referrer-Policy no-referrer" "no-referrer" "$(cat "$WORK/page.headers")"
absent "served page contains no literal admin token" "$TOKEN" "$(cat "$PAGE")"

log "== node 无头验证 hash 解析与清除 =="
NODE_BIN="$(command -v node || true)"
if [ -n "$NODE_BIN" ]; then
  cat >"$WORK/hash-harness.js" <<'JSEOF'
const fs = require("fs");
const html = fs.readFileSync(process.argv[2], "utf8");
const match = html.match(/function consumeTokenFromHash\(\) \{[\s\S]*?\n\}/);
if (!match) { console.log(JSON.stringify({ error: "consumeTokenFromHash not found" })); process.exit(0); }
const src = match[0];
function run(hash) {
  const calls = [];
  const win = {
    location: { hash, pathname: "/", search: "" },
    history: { replaceState: (...args) => calls.push(args) },
  };
  const fn = new Function("window", "URLSearchParams", src + "\nreturn consumeTokenFromHash();");
  const token = fn(win, URLSearchParams);
  return { token, calls };
}
console.log(JSON.stringify({
  withToken: run("#token=abc123"),
  percentEncoded: run("#token=abc%2B123"),
  noHash: run(""),
  otherFragment: run("#foo=1"),
}));
JSEOF
  NODE_OUT="$("$NODE_BIN" "$WORK/hash-harness.js" "$PAGE")"
  check "hash login: token is parsed" "abc123" "$(printf '%s' "$NODE_OUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["withToken"]["token"])')"
  check "hash login: hash is cleared once" "1" "$(printf '%s' "$NODE_OUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d["withToken"]["calls"]))')"
  check "hash login: cleared to the bare path" "/" "$(printf '%s' "$NODE_OUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["withToken"]["calls"][0][2])')"
  check "hash login: percent-encoded token is decoded" "abc+123" "$(printf '%s' "$NODE_OUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["percentEncoded"]["token"])')"
  check "hash login: no hash returns no token" "" "$(printf '%s' "$NODE_OUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["noHash"]["token"])')"
  check "hash login: no hash leaves history alone" "0" "$(printf '%s' "$NODE_OUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d["noHash"]["calls"]))')"
  check "hash login: unrelated fragment is untouched" "0" "$(printf '%s' "$NODE_OUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d["otherFragment"]["calls"]))')"
  NODE_STATE="node $("$NODE_BIN" --version)"
else
  CHECKS+=("FAIL|node hash harness|node not installed")
  NODE_STATE="absent"
fi

log "== Go 构建 =="
set +e
BUILD_OUT="$("${GOENV[@]}" go build ./... 2>&1)"; BUILD_CODE=$?
set -e
check "go build ./... passes" "0" "$BUILD_CODE"

log "== 写验收结果 =="
printf '%s\n' "${CHECKS[@]}" >"$WORK/checks.txt"
python3 - "$WORK/checks.txt" "$OUT_DIR/result.json" "$ADMIN" "$NODE_STATE" "$BUILD_OUT" "$OPEN_OUT" <<'PY'
import json, sys, datetime, platform, subprocess

checks_path, out_path, admin, node_state, build_out, open_out = sys.argv[1:7]
checks = []
for line in open(checks_path, encoding="utf-8"):
    line = line.rstrip("\n")
    if not line:
        continue
    status, name, detail = line.split("|", 2)
    checks.append({"name": name, "status": status, "detail": detail})
passed = sum(1 for c in checks if c["status"] == "PASS")
failed = len(checks) - passed

def version(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip().splitlines()[0]
    except Exception:
        return "unknown"

result = {
    "phase": "ui-login",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "environment": {
        "os": platform.platform(),
        "machine": platform.machine(),
        "go": version(["go", "version"]),
        "node": node_state,
        "admin_address": admin,
    },
    "summary": {"total": len(checks), "passed": passed, "failed": failed},
    "checks": checks,
    "behavior": {
        "command": "keykoi ui [--admin ADDR] [--no-open]",
        "link": "http://<admin>/#token=<admin.token>",
        "token_handling": [
            "令牌只出现在 URL fragment，不进入请求行，因此服务端访问日志里没有令牌。",
            "页面加载时读取 location.hash 的 token=、填入登录框并自动连接，随后立即 history.replaceState 清除 hash。",
            "默认模式（打开浏览器）不把令牌写到 stdout/stderr；--no-open 打印一次登录链接以便手动复制。",
            "管理页面本身带 Referrer-Policy: no-referrer，fragment 也不会随 Referer 外泄。",
        ],
        "no_open": "--no-open 只打印登录链接与说明，不启动浏览器；自动化用它断言 URL 构造。",
        "scope": "只打开回环管理地址；地址来源是后台实际监听地址或 --admin。",
    },
    "go": {
        "build": "pass" if build_out == "" or "error" not in build_out.lower() else "fail",
        "build_output": build_out.strip(),
    },
    "commands": {
        "rerun": "bash tests/acceptance/ui-login.sh",
        "manual": "keykoi init && keykoi ui（浏览器应自动登录，地址栏里不残留 #token=）",
    },
}
import os
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(result, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
print(f"wrote {out_path}: {passed}/{len(checks)} checks passed")
PY

FAILED_COUNT=0
for line in "${CHECKS[@]}"; do
  case "$line" in FAIL\|*) FAILED_COUNT=$((FAILED_COUNT + 1));; esac
done
if [ "$FAILED_COUNT" -ne 0 ]; then
  log "FAILED checks: $FAILED_COUNT"
  exit 1
fi
log "all ui login acceptance checks passed"
