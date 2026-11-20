#!/usr/bin/env bash
# P4 SSH Agent 验收：受保护的本地 agent、授权枚举、真实 OpenSSH 客户端签名与撤销。
#
# 全部材料在运行时生成：测试用户密钥、sshd 主机密钥、密钥库密码与凭证都只存在于
# 本次临时目录。脚本不写入 ~/Library/Application Support/KeyKoi，也不写真实密钥。
#
# 验证路径（result.json 的 verification_paths 会记录实际使用情况）：
#   1) 受控 sshd（非 root，仅回环，仅公钥）上的真实 SSH 认证；
#   2) ssh-keygen -Y sign / -Y verify 对同一 agent 的真实 OpenSSH 签名验证。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/验收/artifacts/p4-ssh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keykoi-p4ssh.XXXXXX")"
BIN="$WORK/bin"
LOG_FILE="$OUT_DIR/p4-ssh.log"
mkdir -p "$BIN" "$OUT_DIR" "$WORK/keys" "$WORK/pub" "$WORK/sshd" "$WORK/data"
: >"$LOG_FILE"

log() { printf '%s\n' "$*" | tee -a "$LOG_FILE" >&2; }
fail() { log "FAIL: $*"; exit 1; }

cleanup() {
  set +e
  [ -n "${ED_AGENT_PID:-}" ] && kill "$ED_AGENT_PID" 2>/dev/null
  [ -n "${RSA_AGENT_PID:-}" ] && kill "$RSA_AGENT_PID" 2>/dev/null
  [ -n "${TOKEN_AGENT_PID:-}" ] && kill "$TOKEN_AGENT_PID" 2>/dev/null
  [ -n "${SSHD_PID:-}" ] && kill "$SSHD_PID" 2>/dev/null
  [ -n "${KEYKOID_PID:-}" ] && kill "$KEYKOID_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

CHECKS=()
check() { # name expected actual
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    CHECKS+=("PASS|$name|$actual")
    log "PASS $name ($actual)"
  else
    CHECKS+=("FAIL|$name|expected=$expected actual=$actual")
    log "FAIL $name expected=$expected actual=$actual"
  fi
}

cd "$ROOT"
log "building binaries"
go build -o "$BIN/keykoi" ./cmd/keykoi
go build -o "$BIN/keykoid" ./cmd/keykoid

# 数据目录只落在临时目录；CLI 通过环境变量指向同一个后台。
DATA="$WORK/data"
export KEYKOI_DATA_DIR="$DATA"
UID_NUM="$(id -u)"
CLIENT_PRINCIPAL="principal_local_$UID_NUM"

log "generating runtime test keys (ssh-keygen)"
ssh-keygen -t ed25519 -N '' -C "keykoi-p4-ed25519" -f "$WORK/keys/ed25519" >/dev/null
ssh-keygen -t rsa -b 2048 -N '' -C "keykoi-p4-rsa" -f "$WORK/keys/rsa" >/dev/null
ssh-keygen -t ed25519 -N '' -C "keykoi-p4-sshd-hostkey" -f "$WORK/sshd/hostkey" >/dev/null
# 私钥只留在 keys/。签名命令使用 pub/ 下的公钥，路径同名私钥不存在，
# 因此 OpenSSH 必须经由 SSH_AUTH_SOCK 请求 agent 签名。
cp "$WORK/keys/ed25519.pub" "$WORK/pub/ed25519.pub"
cp "$WORK/keys/rsa.pub" "$WORK/pub/rsa.pub"
chmod 600 "$WORK/pub/ed25519.pub" "$WORK/pub/rsa.pub"
cp "$WORK/keys/ed25519.pub" "$WORK/sshd/authorized_keys"
chmod 600 "$WORK/sshd/authorized_keys"
ED_FP="$(ssh-keygen -lf "$WORK/pub/ed25519.pub" | awk '{print $2}')"
RSA_FP="$(ssh-keygen -lf "$WORK/pub/rsa.pub" | awk '{print $2}')"
log "fixture fingerprints: ed25519=$ED_FP rsa=$RSA_FP"

log "starting keykoid (encrypted vault backend, temporary data dir)"
"$BIN/keykoid" --data-dir "$DATA" --gateway 127.0.0.1:0 --admin 127.0.0.1:0 >"$WORK/keykoid.log" 2>&1 &
KEYKOID_PID=$!
for i in $(seq 1 80); do "$BIN/keykoi" status >/dev/null 2>&1 && break; sleep 0.1; done
"$BIN/keykoi" status >/dev/null 2>&1 || fail "keykoid did not become reachable"

MASTER_PW="$(openssl rand -hex 16)"
printf '%s\n' "$MASTER_PW" | "$BIN/keykoi" init --password-stdin >/dev/null
log "vault initialized with a runtime-generated password"

log "seeding ssh_key credentials, bindings and sign grants"
ED_CRED="$("$BIN/keykoi" --json credential add --kind ssh_key --label "p4 ssh ed25519" \
  --field "private_key=$(cat "$WORK/keys/ed25519")" | tr -d '\n')"
RSA_CRED="$("$BIN/keykoi" --json credential add --kind ssh_key --label "p4 ssh rsa" \
  --field "private_key=$(cat "$WORK/keys/rsa")" | tr -d '\n')"
[ -n "$ED_CRED" ] || fail "could not create ed25519 ssh_key credential"
[ -n "$RSA_CRED" ] || fail "could not create rsa ssh_key credential"

# SSH 不走 HTTP；origin 只是占位，登记仍然要求一个合法 scheme://host:port。
"$BIN/keykoi" --json binding add --id bind_p4_ed --credential "$ED_CRED" \
  --origin http://127.0.0.1:1 --route p4-ssh-ed --scheme bearer >/dev/null
"$BIN/keykoi" --json binding add --id bind_p4_rsa --credential "$RSA_CRED" \
  --origin http://127.0.0.1:1 --route p4-ssh-rsa --scheme bearer >/dev/null
ED_GRANT="$("$BIN/keykoi" --json grant add --principal "$CLIENT_PRINCIPAL" --binding bind_p4_ed \
  --mode sign --auth permanent --max-lease-seconds 600 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
"$BIN/keykoi" --json grant add --principal "$CLIENT_PRINCIPAL" --binding bind_p4_rsa \
  --mode sign --auth permanent --max-lease-seconds 600 >/dev/null
[ -n "$ED_GRANT" ] || fail "could not create the ed25519 sign grant"
log "grant=$ED_GRANT principal=$CLIENT_PRINCIPAL"

SESSION_TOKEN="$(python3 - "$DATA" <<'PY'
import http.client, socket, json, os, sys
sock = os.path.join(sys.argv[1], "keykoid.sock")

class UHTTP(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("keykoi.local")

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(sock)

c = UHTTP()
c.request("POST", "/v1/sessions", json.dumps({"purpose": "p4-ssh-acceptance"}),
          {"Content-Type": "application/json"})
print(json.loads(c.getresponse().read())["token"])
PY
)"
[ -n "$SESSION_TOKEN" ] || fail "could not create a local session"

log "P4.1: /v1/ssh-keys returns metadata only"
KEYS_JSON="$(python3 - "$DATA" "$SESSION_TOKEN" <<'PY'
import http.client, socket, json, os, sys
sock = os.path.join(sys.argv[1], "keykoid.sock")

class UHTTP(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("keykoi.local")

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(sock)

c = UHTTP()
c.request("POST", "/v1/ssh-keys", json.dumps({"token": sys.argv[2]}),
          {"Content-Type": "application/json"})
r = c.getresponse()
body = r.read().decode()
sys.stderr.write("ssh-keys status=%d\n" % r.status)
print(body)
PY
)" 2>>"$LOG_FILE"
printf '%s' "$KEYS_JSON" >"$WORK/ssh-keys.json"
check "ssh-keys lists both sign-granted ssh_key credentials" "2" \
  "$(printf '%s' "$KEYS_JSON" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["keys"]))')"
check "ssh-keys response has no private key field" "0" \
  "$(printf '%s' "$KEYS_JSON" | python3 -c 'import json,sys; print(1 if "private_key" in sys.stdin.read() else 0)')"
check "ssh-keys response has no private key material" "0" \
  "$(printf '%s' "$KEYS_JSON" | python3 -c 'import sys; print(1 if "PRIVATE KEY" in sys.stdin.read() else 0)')"
check "ssh-keys reports ed25519 key fingerprint" "$ED_FP" \
  "$(printf '%s' "$KEYS_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); print([k["fingerprint"] for k in d["keys"] if k["binding_id"]=="bind_p4_ed"][0])')"
check "ssh-keys reports rsa key algorithm" "ssh-rsa" \
  "$(printf '%s' "$KEYS_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); print([k["algorithm"] for k in d["keys"] if k["binding_id"]=="bind_p4_rsa"][0])')"

log "P4.1: starting keykoi ssh-agent"
"$BIN/keykoi" ssh-agent --binding bind_p4_ed --socket "$WORK/agent-ed.sock" \
  >"$WORK/agent-ed.out" 2>"$WORK/agent-ed.err" &
ED_AGENT_PID=$!
"$BIN/keykoi" ssh-agent --binding bind_p4_rsa --socket "$WORK/agent-rsa.sock" \
  >"$WORK/agent-rsa.out" 2>"$WORK/agent-rsa.err" &
RSA_AGENT_PID=$!
for i in $(seq 1 80); do
  [ -S "$WORK/agent-ed.sock" ] && [ -S "$WORK/agent-rsa.sock" ] && break
  sleep 0.1
done
[ -S "$WORK/agent-ed.sock" ] || fail "ed25519 agent socket did not appear"
[ -S "$WORK/agent-rsa.sock" ] || fail "rsa agent socket did not appear"
log "agent stdout: $(head -1 "$WORK/agent-ed.out")"

check "agent socket is owner-only (0600)" "600" "$(stat -f '%Lp' "$WORK/agent-ed.sock")"
check "agent socket directory is owner-only" "700" "$(stat -f '%Lp' "$WORK")"

log "P4.2.1: enumerate through the real OpenSSH client (ssh-add -l)"
ED_LIST="$(SSH_AUTH_SOCK="$WORK/agent-ed.sock" ssh-add -l 2>&1 || true)"
printf '%s\n' "$ED_LIST" >>"$LOG_FILE"
check "ssh-add -l enumerates exactly one key for this binding" "1" "$(printf '%s\n' "$ED_LIST" | grep -c 'ED25519' || true)"
check "ssh-add -l reports the managed key fingerprint" "$ED_FP" "$(printf '%s\n' "$ED_LIST" | awk '{print $2}')"
check "agent does not enumerate the other binding's key" "0" "$(printf '%s\n' "$ED_LIST" | grep -c 'RSA' || true)"

log "P4.2.2: real SSH authentication against a controlled sshd"
PORT="$(python3 -c 'import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
cat >"$WORK/sshd/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $WORK/sshd/hostkey
PidFile $WORK/sshd/sshd.pid
AuthorizedKeysFile $WORK/sshd/authorized_keys
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
LogLevel VERBOSE
EOF
/usr/sbin/sshd -D -e -f "$WORK/sshd/sshd_config" >"$WORK/sshd/log" 2>&1 &
SSHD_PID=$!
SSHD_READY=0
for i in $(seq 1 80); do
  if nc -z 127.0.0.1 "$PORT" >/dev/null 2>&1; then SSHD_READY=1; break; fi
  sleep 0.1
done
[ "$SSHD_READY" = "1" ] || fail "controlled sshd did not listen on 127.0.0.1:$PORT"

SSH_BASE=(-F /dev/null -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
  -o BatchMode=yes -o ConnectTimeout=10 -o "IdentityAgent=$WORK/agent-ed.sock"
  -o IdentitiesOnly=yes -i "$WORK/pub/ed25519.pub")

SSH_OUT="$(SSH_AUTH_SOCK="$WORK/agent-ed.sock" ssh "${SSH_BASE[@]}" "$(id -un)@127.0.0.1" \
  'echo KEYKOI_SSH_OK' 2>"$WORK/ssh-auth.err" || true)"
printf '%s\n' "$SSH_OUT" >>"$LOG_FILE"
check "real sshd accepts agent-authenticated login" "KEYKOI_SSH_OK" "$(printf '%s' "$SSH_OUT" | tail -1)"
check "sshd log records an accepted publickey for the managed key" "1" \
  "$(grep -c 'Accepted publickey for' "$WORK/sshd/log" 2>/dev/null || echo 0)"

log "P4.2.3: signature interoperability (ssh-keygen -Y sign / -Y verify)"
printf 'p4 ssh agent payload\n' >"$WORK/payload.txt"
printf 'p4 ssh agent rsa payload\n' >"$WORK/payload-rsa.txt"
{
  printf 'p4-ed25519 %s\n' "$(cat "$WORK/pub/ed25519.pub")"
  printf 'p4-rsa %s\n' "$(cat "$WORK/pub/rsa.pub")"
} >"$WORK/allowed_signers"

ED_SIGN_OK=0
if (cd "$WORK" && SSH_AUTH_SOCK="$WORK/agent-ed.sock" ssh-keygen -Y sign \
  -f "$WORK/pub/ed25519.pub" -n keykoi-p4 payload.txt >/dev/null 2>"$WORK/sign-ed.err"); then
  ED_SIGN_OK=1
fi
ED_VERIFY="$( (cd "$WORK" && ssh-keygen -Y verify -f allowed_signers -I p4-ed25519 \
  -n keykoi-p4 -s payload.txt.sig <payload.txt 2>&1) || true)"
printf '%s\n' "$ED_VERIFY" >>"$LOG_FILE"
check "ed25519 signature produced through the agent" "1" "$ED_SIGN_OK"
check "ed25519 signature verifies with ssh-keygen -Y verify" "1" \
  "$(printf '%s' "$ED_VERIFY" | grep -c '^Good' || true)"

RSA_SIGN_OK=0
if (cd "$WORK" && SSH_AUTH_SOCK="$WORK/agent-rsa.sock" ssh-keygen -Y sign \
  -f "$WORK/pub/rsa.pub" -n keykoi-p4 payload-rsa.txt >/dev/null 2>"$WORK/sign-rsa.err"); then
  RSA_SIGN_OK=1
fi
RSA_VERIFY="$( (cd "$WORK" && ssh-keygen -Y verify -f allowed_signers -I p4-rsa \
  -n keykoi-p4 -s payload-rsa.txt.sig <payload-rsa.txt 2>&1) || true)"
printf '%s\n' "$RSA_VERIFY" >>"$LOG_FILE"
check "rsa signature produced through the agent" "1" "$RSA_SIGN_OK"
check "rsa signature verifies with ssh-keygen -Y verify" "1" \
  "$(printf '%s' "$RSA_VERIFY" | grep -c '^Good' || true)"

RSA_SIG_ALGO="$(python3 - "$WORK/payload-rsa.txt.sig" <<'PY'
import base64, struct, sys

def rd(buf, off):
    (n,) = struct.unpack(">I", buf[off:off + 4])
    off += 4
    return buf[off:off + n], off + n

lines = [l for l in open(sys.argv[1], "rb").read().splitlines()
         if not l.startswith(b"-----")]
data = base64.b64decode(b"".join(lines))
if data[:6] != b"SSHSIG":
    raise SystemExit("unexpected signature magic")
off = 6                            # magic is the literal "SSHSIG"
struct.unpack(">I", data[off:off + 4]); off += 4  # version
_, off = rd(data, off)            # public key blob
_, off = rd(data, off)            # namespace
_, off = rd(data, off)            # reserved
_, off = rd(data, off)            # hash algorithm
sig, _ = rd(data, off)            # signature blob
algo, _ = rd(sig, 0)
print(algo.decode())
PY
)"
RSA_SIG_IS_SHA2="$(python3 -c 'import sys; print(1 if sys.argv[1] in ("rsa-sha2-256", "rsa-sha2-512") else 0)' "$RSA_SIG_ALGO")"
check "rsa signature uses an rsa-sha2 variant (agent signature flags)" "1" "$RSA_SIG_IS_SHA2"
log "rsa signature algorithm: $RSA_SIG_ALGO"

log "P4.1: agent started with a caller-provided session token"
TOKEN_AGENT_SOCK="$WORK/agent-token.sock"
"$BIN/keykoi" ssh-agent --binding bind_p4_rsa --socket "$TOKEN_AGENT_SOCK" \
  --session-token "$SESSION_TOKEN" >"$WORK/agent-token.out" 2>"$WORK/agent-token.err" &
TOKEN_AGENT_PID=$!
for i in $(seq 1 80); do [ -S "$TOKEN_AGENT_SOCK" ] && break; sleep 0.1; done
TOKEN_LIST="$(SSH_AUTH_SOCK="$TOKEN_AGENT_SOCK" ssh-add -l 2>&1 || true)"
printf '%s\n' "$TOKEN_LIST" >>"$LOG_FILE"
check "agent honours an externally created session token" "1" \
  "$(printf '%s\n' "$TOKEN_LIST" | grep -c 'RSA' || true)"
check "token-backed agent reports the managed rsa fingerprint" "$RSA_FP" \
  "$(printf '%s' "$TOKEN_LIST" | awk '{print $2}')"
kill -TERM "$TOKEN_AGENT_PID" 2>/dev/null || true
wait "$TOKEN_AGENT_PID" 2>/dev/null || true
unset TOKEN_AGENT_PID

log "P4.2.4: establish a long-lived session before revocation"
SSH_AUTH_SOCK="$WORK/agent-ed.sock" ssh "${SSH_BASE[@]}" "$(id -un)@127.0.0.1" \
  'sleep 3; echo DONE_FROM_EXISTING' >"$WORK/existing.out" 2>"$WORK/existing.err" &
EXISTING_PID=$!
sleep 1.5

log "P4.2.5: revoke the sign grant"
"$BIN/keykoi" grant revoke --id "$ED_GRANT" >/dev/null
log "grant $ED_GRANT revoked"

EXISTING_RC=0
wait "$EXISTING_PID" 2>/dev/null || EXISTING_RC=$?
check "existing connection behaviour recorded after revocation" "DONE_FROM_EXISTING" \
  "$(tail -1 "$WORK/existing.out" 2>/dev/null || echo "no-output")"
log "existing connection exit=$EXISTING_RC (actual result recorded, not asserted)"

NEW_SSH_OUT="$(SSH_AUTH_SOCK="$WORK/agent-ed.sock" ssh "${SSH_BASE[@]}" \
  "$(id -un)@127.0.0.1" 'echo SHOULD_NOT_AUTHENTICATE' 2>&1 || true)"
printf '%s\n' "$NEW_SSH_OUT" >>"$LOG_FILE"
check "new sshd authentication rejected after revocation" "1" \
  "$(printf '%s' "$NEW_SSH_OUT" | grep -c 'Permission denied' || true)"

AFTER_LIST="$(SSH_AUTH_SOCK="$WORK/agent-ed.sock" ssh-add -l 2>&1 || true)"
printf '%s\n' "$AFTER_LIST" >>"$LOG_FILE"
check "enumeration is empty after revocation" "The agent has no identities." \
  "$(printf '%s' "$AFTER_LIST" | head -1)"

printf 'after revocation\n' >"$WORK/payload-after.txt"
AFTER_SIGN_RC=0
(cd "$WORK" && SSH_AUTH_SOCK="$WORK/agent-ed.sock" ssh-keygen -Y sign \
  -f "$WORK/pub/ed25519.pub" -n keykoi-p4 payload-after.txt >/dev/null 2>"$WORK/sign-after.err") \
  || AFTER_SIGN_RC=$?
check "signing denied after revocation" "1" "$([ "$AFTER_SIGN_RC" -ne 0 ] && echo 1 || echo 0)"
check "no signature file produced after revocation" "0" \
  "$([ -e "$WORK/payload-after.txt.sig" ] && echo 1 || echo 0)"
log "post-revocation sign error: $(head -1 "$WORK/sign-after.err" 2>/dev/null || echo '-')"

RESOLVE_RESULT="$(python3 - "$DATA" "$SESSION_TOKEN" <<'PY'
import http.client, socket, json, os, sys
sock = os.path.join(sys.argv[1], "keykoid.sock")

class UHTTP(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("keykoi.local")

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(sock)

c = UHTTP()
c.request("POST", "/v1/resolve",
          json.dumps({"token": sys.argv[2], "binding_id": "bind_p4_ed", "mode": "sign"}),
          {"Content-Type": "application/json"})
r = c.getresponse()
body = r.read().decode()
try:
    code = json.loads(body)["error"]["code"]
except Exception:
    code = "none"
print("%d %s" % (r.status, code))
PY
)"
check "daemon denies sign resolution after revocation" "403 USE_NOT_ALLOWED" "$RESOLVE_RESULT"

log "P4.2.6: audit and log boundaries"
AUDIT_JSON="$("$BIN/keykoi" --json audit --limit 200)"
printf '%s' "$AUDIT_JSON" >"$WORK/audit.json"
check "audit records at least one allowed sign request" "1" \
  "$([ "$(printf '%s' "$AUDIT_JSON" | python3 -c 'import json,sys; ev=json.load(sys.stdin); print(len([e for e in ev if e["Mode"]=="sign" and e["Result"]=="allowed"]))')" -ge 1 ] && echo 1 || echo 0)"
check "audit records the denied sign request" "1" \
  "$([ "$(printf '%s' "$AUDIT_JSON" | python3 -c 'import json,sys; ev=json.load(sys.stdin); print(len([e for e in ev if e["Mode"]=="sign" and e["Result"]=="denied"]))')" -ge 1 ] && echo 1 || echo 0)"
check "audit contains no key material" "0" \
  "$(printf '%s' "$AUDIT_JSON" | python3 -c 'import sys; d=sys.stdin.read(); print(1 if ("PRIVATE KEY" in d or "OPENSSH PRIVATE" in d) else 0)')"
check "daemon log contains no key material" "0" \
  "$(cat "$WORK/keykoid.log" | python3 -c 'import sys; d=sys.stdin.read(); print(1 if ("PRIVATE KEY" in d or "OPENSSH PRIVATE" in d) else 0)')"
check "agent log contains no key material" "0" \
  "$(cat "$WORK/agent-ed.err" "$WORK/agent-rsa.err" 2>/dev/null | python3 -c 'import sys; d=sys.stdin.read(); print(1 if ("PRIVATE KEY" in d or "OPENSSH PRIVATE" in d) else 0)')"

log "P4.2.7: SIGTERM cleanup"
kill -TERM "$ED_AGENT_PID" 2>/dev/null || true
ED_AGENT_WAIT=0
for i in $(seq 1 80); do
  if ! kill -0 "$ED_AGENT_PID" 2>/dev/null; then ED_AGENT_WAIT=1; break; fi
  sleep 0.1
done
check "agent exits on SIGTERM" "1" "$ED_AGENT_WAIT"
check "agent removes its socket on exit" "1" "$([ -e "$WORK/agent-ed.sock" ] && echo 0 || echo 1)"
unset ED_AGENT_PID

HOST_OS="$(sw_vers -productVersion)"
ARCH="$(uname -m)"
OPENSSH_VERSION="$(ssh -V 2>&1 | head -1)"
GO_VERSION="$(go version | awk '{print $3}')"

python3 - "$OUT_DIR/result.json" "$HOST_OS" "$ARCH" "$OPENSSH_VERSION" "$GO_VERSION" \
  "$ED_FP" "$RSA_FP" "$PORT" "$RSA_SIG_ALGO" "${CHECKS[@]}" <<'PY'
import json, sys

out_dir = sys.argv[1]
checks = []
for raw in sys.argv[10:]:
    parts = raw.split("|", 2)
    checks.append({"status": parts[0], "name": parts[1],
                   "detail": parts[2] if len(parts) > 2 else ""})
failed = [c for c in checks if c["status"] != "PASS"]
result = {
    "phase": "p4-ssh-agent",
    "generated_at": __import__("datetime").datetime.now().astimezone().isoformat(),
    "verification_paths": [
        "real sshd (loopback 127.0.0.1:%s, non-root, pubkey only) authenticated through SSH_AUTH_SOCK" % sys.argv[8],
        "ssh-keygen -Y sign / -Y verify against the same agent for ed25519 and rsa",
    ],
    "environment": {
        "os": "macOS %s" % sys.argv[2],
        "arch": sys.argv[3],
        "openssh": sys.argv[4],
        "go": sys.argv[5],
        "daemon_backend": "encrypted SQLite vault (temporary --data-dir, did not touch ~/Library/Application Support/KeyKoi)",
        "test_material": "runtime-generated by ssh-keygen and openssl; no real credentials used",
        "managed_key_fingerprints": {"ed25519": sys.argv[6], "rsa": sys.argv[7]},
        "rsa_signature_algorithm_via_agent": sys.argv[9],
    },
    "commands": [
        "keykoid --data-dir $DATA --gateway 127.0.0.1:0 --admin 127.0.0.1:0",
        "keykoi init --password-stdin",
        "keykoi credential add --kind ssh_key --label 'p4 ssh ed25519' --field private_key=<generated>",
        "keykoi binding add --id bind_p4_ed --origin http://127.0.0.1:1 --route p4-ssh-ed --scheme bearer",
        "keykoi grant add --principal principal_local_$(id -u) --binding bind_p4_ed --mode sign",
        "keykoi ssh-agent --binding bind_p4_ed --socket $WORK/agent-ed.sock",
        "SSH_AUTH_SOCK=$WORK/agent-ed.sock ssh-add -l",
        "SSH_AUTH_SOCK=$WORK/agent-ed.sock ssh -p $PORT -o IdentityAgent=$WORK/agent-ed.sock -i pub/ed25519.pub user@127.0.0.1 'echo KEYKOI_SSH_OK'",
        "SSH_AUTH_SOCK=$WORK/agent-ed.sock ssh-keygen -Y sign -f pub/ed25519.pub -n keykoi-p4 payload.txt",
        "ssh-keygen -Y verify -f allowed_signers -I p4-ed25519 -n keykoi-p4 -s payload.txt.sig",
        "keykoi grant revoke --id $ED_GRANT",
        "POST /v1/ssh-keys {token} (metadata only)",
        "POST /v1/resolve {binding_id: bind_p4_ed, mode: sign} after revocation",
    ],
    "checks": checks,
    "summary": {"total": len(checks), "failed": len(failed)},
}
json.dump(result, open(out_dir, "w"), indent=2, ensure_ascii=False)
print("checks=%d failed=%d" % (len(checks), len(failed)))
PY

if grep -q '"failed": 0' "$OUT_DIR/result.json"; then
  log "P4 ssh-agent acceptance PASSED"
else
  log "P4 ssh-agent acceptance has failures; see $OUT_DIR/result.json"
  exit 1
fi
