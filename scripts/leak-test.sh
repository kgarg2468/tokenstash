#!/usr/bin/env bash
# Black-box leak test: drive the real binary with a canary secret and assert the canary never
# appears on stdout/stderr, in the database, the config, the audit log, or MCP output.
set -euo pipefail
TS="$(cd "$(dirname "${1:-target/debug/tokenstash}")" && pwd)/$(basename "${1:-target/debug/tokenstash}")"
export TOKENSTASH_HOME="$(mktemp -d)"
export TOKENSTASH_STASH=insecure-file
PROJ="$(mktemp -d)"; cd "$PROJ"; git init -q .
OUT="$(mktemp -d)"
# Browser-facing responses legitimately contain the inbox session token (the hidden CSRF
# field), so every curl body lands in $WEB. $OUT is the agent/CLI-facing surface, and the
# token must never appear there — see assertion (d).
WEB="$(mktemp -d)"
JAR="$(mktemp)"
CANARY="sk-LEAKCANARY-$(date +%s)-0123456789abcdef"

# A temp TOKENSTASH_HOME isolates the config and the database but NOT the OS credential
# store: the Linux kernel keyring is per-USER, so a canary stashed there outlives the run
# and turns up in the developer's next real session. Two defences, in this order:
#   1. pin the insecure-file backend (environment above, config below) and refuse to store
#      anything until the binary itself confirms that is the backend in use;
#   2. forget everything this run stashed, and delete the dirs holding the canary, on exit.
cleanup() {
    kill "${INBOX_PID:-}" "${SQUAT_PID:-}" 2>/dev/null || true
    cd / || true
    # every secret the isolated stash knows about is a canary this run created
    "$TS" list 2>/dev/null | awk '$1 != "NAME" && $1 ~ /^[A-Z][A-Z0-9_]*$/ { print $1, $2 }' \
        | while read -r n i; do "$TS" forget "$n" --identity "$i" >/dev/null 2>&1 || true; done
    # $WEB and $JAR hold authenticated pages and the session cookie, so they always go
    rm -rf "$TOKENSTASH_HOME" "$PROJ" "$WEB" "$JAR" || true
    # keep $OUT for debugging unless it turns out to hold the canary itself
    if grep -rq "$CANARY" "$OUT" 2>/dev/null; then rm -rf "$OUT" || true; fi
    return 0
}
trap cleanup EXIT

"$TS" init --no-agents --trust "$PROJ" >"$OUT/init.txt" 2>&1 || true
# Own the inbox for this run: a dedicated port, started by us, killed by PID. Never touch
# whatever real inbox the developer may have running.
PORT=$(( 20000 + RANDOM % 20000 ))
sed -i.bak -e "s/^inbox_port = .*/inbox_port = $PORT/" -e "s/^notifications = .*/notifications = false/" "$TOKENSTASH_HOME/config.toml"
printf 'stash_backend = "insecure-file"\n' >> "$TOKENSTASH_HOME/config.toml"
"$TS" doctor >"$OUT/doctor-pre.txt" 2>&1 || true
grep -qE "stash backend +insecure-file" "$OUT/doctor-pre.txt" || {
    echo "refusing to run: the stash backend is not isolated, a canary would land in the real keyring"
    sed -n 's/^.*stash backend/stash backend/p' "$OUT/doctor-pre.txt"; exit 1
}
"$TS" inbox --port "$PORT" --keep >"$OUT/inbox.txt" 2>&1 &
INBOX_PID=$!
# /health now needs the session token like every other route; /verify is the unauthenticated
# ownership challenge, so it is also the readiness probe.
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/verify?c=ready" >/dev/null 2>&1 && break; sleep 0.1; done
"$TS" need OPENAI_API_KEY AUTH_SECRET --agent ci --why "leak test" >"$OUT/need1.txt" 2>&1 || true
TID=$("$TS" tasks --json | python3 -c "import json,sys;print([t for t in json.load(sys.stdin) if t.get('name')=='OPENAI_API_KEY'][0]['id'])")
echo "$CANARY" | "$TS" answer "$TID" --stdin --skip-check >"$OUT/answer.txt" 2>&1
"$TS" need OPENAI_API_KEY --agent ci --json >"$OUT/need2.txt" 2>&1
"$TS" list >"$OUT/list.txt" 2>&1
"$TS" tasks --all --history --json >"$OUT/tasks.txt" 2>&1
"$TS" audit >"$OUT/audit.txt" 2>&1
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"ci"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"secrets_request","arguments":{"secrets":[{"name":"OPENAI_API_KEY"}],"project":"'"$PROJ"'"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secrets_list","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"task_list","arguments":{"all":true}}}' \
  | "$TS" mcp >"$OUT/mcp.txt" 2>&1
"$TS" doctor >"$OUT/doctor.txt" 2>&1 || true

# run shim: a child that echoes its environment must not leak the injected value
cat > "$PROJ/echo.sh" <<'SH'
#!/bin/sh
echo "env dump: OPENAI_API_KEY=$OPENAI_API_KEY"
echo "stderr: $OPENAI_API_KEY" >&2
exit 0
SH
chmod +x "$PROJ/echo.sh"
"$TS" run -- "$PROJ/echo.sh" >"$OUT/run.txt" 2>&1 || true
grep -q "\[redacted\]" "$OUT/run.txt" || { echo "run shim did not redact"; exit 1; }
# ...and an inherited parent-environment secret under a secret-looking name is redacted too
INHERITED="inherited-LEAKCANARY-$(date +%s)-zzzz"
cat > "$PROJ/echo2.sh" <<'SH'
#!/bin/sh
echo "MY_SERVICE_TOKEN is $MY_SERVICE_TOKEN"
SH
chmod +x "$PROJ/echo2.sh"
MY_SERVICE_TOKEN="$INHERITED" "$TS" run -- "$PROJ/echo2.sh" >"$OUT/run2.txt" 2>&1 || true
# ...including under a name with no secret-looking substring
cat > "$PROJ/echo3.sh" <<'SH'
#!/bin/sh
echo "cookie=$SESSION_COOKIE path=$PATH"
SH
chmod +x "$PROJ/echo3.sh"
# an EXISTING directory that is a prefix of PATH (a nonexistent one is rightly redacted)
PREFIX_DIR=""; IFS=: ; for d in $PATH; do [ -d "$d" ] && { PREFIX_DIR="$d"; break; }; done; unset IFS
# and the echoed PATH must begin with that existing entry for the assertion to be meaningful
export PATH="$PREFIX_DIR:$PATH"
SESSION_COOKIE="$INHERITED-cookie" MY_TOOL_HOME="$PREFIX_DIR" "$TS" run -- "$PROJ/echo3.sh" >"$OUT/run4.txt" 2>&1 || true
grep -q "$INHERITED-cookie" "$OUT/run4.txt" && { echo "LEAK: inherited SESSION_COOKIE echoed by child"; exit 1; }
grep -q "path=/" "$OUT/run4.txt" || { echo "benign PATH must not be redacted"; exit 1; }
# ...and a secret that merely starts with "/" (no such path) is still redacted
cat > "$PROJ/echo4.sh" <<'SH'
#!/bin/sh
echo "weird=$WEIRD_SECRET"
SH
chmod +x "$PROJ/echo4.sh"
WEIRD_SECRET="/slash-secret-LEAKCANARY-$(date +%s)/x" "$TS" run -- "$PROJ/echo4.sh" >"$OUT/run5.txt" 2>&1 || true
grep -q "slash-secret-LEAKCANARY" "$OUT/run5.txt" && { echo "LEAK: path-like secret echoed by child"; exit 1; }
# ...and even an existing-path secret under a non-allowlisted name is redacted
PATHSECRET="$OUT/tasks2.txt"
cat > "$PROJ/echo5.sh" <<'SH'
#!/bin/sh
echo "dir=$MY_DATA_DIR"
SH
chmod +x "$PROJ/echo5.sh"
MY_DATA_DIR="$PATHSECRET" "$TS" run -- "$PROJ/echo5.sh" >"$OUT/run6.txt" 2>&1 || true
grep -q "dir=$PATHSECRET" "$OUT/run6.txt" && { echo "LEAK: existing-path secret echoed by child"; exit 1; }
grep -q "$INHERITED" "$OUT/run2.txt" && { echo "LEAK: inherited env value echoed by child"; exit 1; }
grep -q "\[redacted\]" "$OUT/run2.txt" || { echo "run shim did not redact inherited value"; exit 1; }

# a secret passed as a command-line argument to `run` must not be persisted in the task text
cat > "$PROJ/fail.sh" <<'SH'
#!/bin/sh
echo "Error: GROQ_API_KEY is not set" >&2; exit 1
SH
chmod +x "$PROJ/fail.sh"
ARGSECRET="argsecret-LEAKCANARY-$(date +%s)"
"$TS" run --timeout 1 -- "$PROJ/fail.sh" --token "$ARGSECRET" >"$OUT/run3.txt" 2>&1 || true
"$TS" tasks --all --history --json >"$OUT/tasks2.txt" 2>&1
grep -q "$ARGSECRET" "$OUT/tasks2.txt" && { echo "LEAK: command argument persisted in task"; exit 1; }

# a registry-named inherited value is redacted even when short (whole-token)
cat > "$PROJ/echo6.sh" <<'SH'
#!/bin/sh
echo "hf token: $HF_TOKEN ok"
SH
chmod +x "$PROJ/echo6.sh"
HF_TOKEN=abc "$TS" run -- "$PROJ/echo6.sh" >"$OUT/run7.txt" 2>&1 || true   # HF_TOKEN=abc
grep -q "hf token: abc ok" "$OUT/run7.txt" && { echo "LEAK: short registry-named value echoed"; exit 1; }

# the env file is the ONE place the value is allowed to be
grep -q "OPENAI_API_KEY=$CANARY" "$PROJ/.env.local"
grep -q "^.env.local$" "$PROJ/.gitignore"

# ── inbox authentication ──────────────────────────────────────────────────────
TOKEN_FILE="$TOKENSTASH_HOME/inbox.token"
[ -s "$TOKEN_FILE" ] || { echo "FAIL: no session token at $TOKEN_FILE — the inbox is unauthenticated"; exit 1; }
TOKEN="$(cat "$TOKEN_FILE")"
MODE="$(stat -c '%a' "$TOKEN_FILE" 2>/dev/null || stat -f '%Lp' "$TOKEN_FILE")"
[ "$MODE" = 600 ] || { echo "FAIL: $TOKEN_FILE is $MODE, expected 600"; exit 1; }

# (a) the live exploit: an unauthenticated POST from any local process — or a loopback
# CSRF from any page the user visits — must not be able to store a value.
"$TS" need EVIL_TARGET_KEY --agent ci --why "inbox auth test" >"$OUT/need-evil.txt" 2>&1 || true
ETID=$("$TS" tasks --json | python3 -c "import json,sys;print([t for t in json.load(sys.stdin) if t.get('name')=='EVIL_TARGET_KEY'][0]['id'])")
code=$(curl -s -o "$WEB/exploit.txt" -w '%{http_code}' -X POST --data 'value=sk-EVIL-INJECTED&skip_check=1' "http://127.0.0.1:$PORT/t/$ETID")
[ "$code" = 404 ] || { echo "FAIL: unauthenticated POST /t/<id> returned $code, expected 404"; exit 1; }
[ -s "$WEB/exploit.txt" ] && { echo "FAIL: the 404 body is not empty — it reveals the inbox"; exit 1; }
grep -q "sk-EVIL-INJECTED" "$PROJ/.env.local" && { echo "FAIL: an unauthenticated POST stored a value"; exit 1; }
code=$(curl -s -o "$WEB/unauth-index.html" -w '%{http_code}' "http://127.0.0.1:$PORT/")
[ "$code" = 404 ] || { echo "FAIL: unauthenticated GET / returned $code, expected 404"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST --data "action=allow" "http://127.0.0.1:$PORT/t/$ETID?t=$TOKEN")
[ "$code" = 404 ] || { echo "FAIL: POST with a query token but no cookie/CSRF field returned $code, expected 404"; exit 1; }
grep -q "sk-EVIL-INJECTED" "$PROJ/.env.local" && { echo "FAIL: a POST without the CSRF field stored a value"; exit 1; }

# (c) /verify is a challenge-response ownership proof, not a token check: it is how the CLI
# learns the listener on the port is OUR inbox for THIS TOKENSTASH_HOME without sending the
# token to a process it has not authenticated yet.
NONCE="nonce-$(date +%s)-$RANDOM"
hmacof() { python3 -c "import hmac,hashlib,sys;print(hmac.new(sys.argv[1].encode(),sys.argv[2].encode(),hashlib.sha256).hexdigest())" "$1" "$2"; }
EXPECT="$(hmacof "$TOKEN" "$NONCE")"
GOT="$(curl -fsS "http://127.0.0.1:$PORT/verify?c=$NONCE")"
[ "$GOT" = "$EXPECT" ] || { echo "FAIL: /verify answered '$GOT', expected HMAC-SHA256(token, nonce) = '$EXPECT'"; exit 1; }
[ "$GOT" != "$TOKEN" ] || { echo "FAIL: /verify echoed the token itself"; exit 1; }
# an impostor holding a different token cannot produce that answer — that is the proof
[ "$GOT" != "$(hmacof "$(printf '0%.0s' $(seq 1 64))" "$NONCE")" ] || { echo "FAIL: /verify is not bound to the token"; exit 1; }
# a replayed answer proves nothing about a later challenge
[ "$GOT" != "$(curl -fsS "http://127.0.0.1:$PORT/verify?c=${NONCE}x")" ] || { echo "FAIL: /verify is not bound to the challenge"; exit 1; }
# ...and /verify without a challenge is a bare 404 like every other unauthorised shape
code=$(curl -s -o "$WEB/verify-noc.txt" -w '%{http_code}' "http://127.0.0.1:$PORT/verify")
[ "$code" = 404 ] || { echo "FAIL: /verify with no challenge returned $code, expected 404"; exit 1; }
[ -s "$WEB/verify-noc.txt" ] && { echo "FAIL: the /verify 404 body is not empty"; exit 1; }
# the CLI uses the same proof before trusting the port (doctor ran while this inbox was up)
grep -q "ownership verified" "$OUT/doctor.txt" || { echo "FAIL: doctor did not verify inbox ownership"; exit 1; }

# (b) the tokened flow still works end to end: ?t= authenticates the first GET, the response
# installs the session cookie, and a POST carrying cookie + hidden field answers the task.
curl -fsS -c "$JAR" -b "$JAR" -L -o "$WEB/task.html" "http://127.0.0.1:$PORT/t/$ETID?t=$TOKEN"
grep -q "tokenstash_inbox" "$JAR" || { echo "FAIL: the tokened GET did not set the session cookie"; exit 1; }
grep -q "name=t value=\"$TOKEN\"" "$WEB/task.html" || { echo "FAIL: the task form carries no CSRF field"; exit 1; }
grep -q "EVIL_TARGET_KEY" "$WEB/task.html" || { echo "FAIL: the authenticated task page did not render"; exit 1; }
# the cookie alone is not enough: without the hidden field this is still a CSRF-shaped post
code=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' --data 'value=sk-EVIL2-INJECTED&skip_check=1' "http://127.0.0.1:$PORT/t/$ETID")
[ "$code" = 404 ] || { echo "FAIL: POST with the cookie but no CSRF field returned $code, expected 404"; exit 1; }
grep -q "sk-EVIL2-INJECTED" "$PROJ/.env.local" && { echo "FAIL: a POST without the CSRF field stored a value"; exit 1; }
# ...and a wrong hidden field is no better than a missing one
code=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' --data "value=sk-EVIL3-INJECTED&skip_check=1&t=$(printf '0%.0s' $(seq 1 64))" "http://127.0.0.1:$PORT/t/$ETID")
[ "$code" = 404 ] || { echo "FAIL: POST with a wrong CSRF field returned $code, expected 404"; exit 1; }
# an answer we could not read to the end is refused outright, not truncated and stored: the
# CSRF field sits at the front of the body, so a cut-off form would still authenticate and the
# prefix of a pasted key would be persisted as though the human had typed it.
"$TS" need BIG_TARGET_KEY --agent ci --why "oversize test" >"$OUT/need-big.txt" 2>&1 || true
BTID=$("$TS" tasks --json | python3 -c "import json,sys;print([t for t in json.load(sys.stdin) if t.get('name')=='BIG_TARGET_KEY'][0]['id'])")
BIG="BIGCANARY-$(head -c 70000 /dev/zero | tr '\0' 'A')"
code=$(curl -s -b "$JAR" -o "$WEB/big.txt" -w '%{http_code}' \
  --data "t=$TOKEN" --data "skip_check=1" --data-urlencode "value=$BIG" "http://127.0.0.1:$PORT/t/$BTID")
[ "$code" = 413 ] || { echo "FAIL: an oversized answer returned $code, expected 413"; exit 1; }
grep -q "BIGCANARY" "$PROJ/.env.local" && { echo "FAIL: a truncated oversized answer was stored"; exit 1; }
"$TS" tasks --json | python3 -c "import json,sys;sys.exit(0 if [t for t in json.load(sys.stdin) if t.get('name')=='BIG_TARGET_KEY' and t['status']=='pending'] else 1)" \
  || { echo "FAIL: the oversized answer changed the task state"; exit 1; }

# the real thing
GOOD="sk-GOODCANARY-$(date +%s)-0123456789abcdef"
curl -fsS -c "$JAR" -b "$JAR" -L -o "$WEB/answered.html" \
  --data-urlencode "value=$GOOD" --data "skip_check=1" --data-urlencode "t=$TOKEN" "http://127.0.0.1:$PORT/t/$ETID"
grep -q "EVIL_TARGET_KEY=$GOOD" "$PROJ/.env.local" || { echo "FAIL: the authenticated answer did not store the value"; exit 1; }
# once the cookie is held, the index needs no token in the URL at all
curl -fsS -b "$JAR" -o "$WEB/index.html" "http://127.0.0.1:$PORT/"
grep -q "tokenstash inbox" "$WEB/index.html" || { echo "FAIL: the cookie alone did not authenticate a GET"; exit 1; }

# a TTY-gated URL must be gated on the stream it is actually printed to. `run` prints its
# inbox line to STDERR, so stdout being a terminal must not token it: here stdout is a pty and
# stderr is a file, which is exactly the shape that captures the token if the check reads the
# wrong stream.
if script -qec true /dev/null >/dev/null 2>&1; then
  script -qec "$TS run --timeout 1 -- $PROJ/fail.sh 2>$OUT/run-stderr.txt" /dev/null >/dev/null 2>&1 || true
  grep -q "$TOKEN" "$OUT/run-stderr.txt" && { echo "FAIL: run tokened a stderr line because stdout happened to be a terminal"; exit 1; }
  grep -q "waiting for you" "$OUT/run-stderr.txt" || { echo "FAIL: run did not print its inbox line, so the check proved nothing"; exit 1; }
fi

fail=0
if grep -rl "$CANARY" "$OUT"; then echo "LEAK: canary found in CLI/MCP output"; fail=1; fi
if grep -q "$CANARY" "$TOKENSTASH_HOME/config.toml" 2>/dev/null; then echo "LEAK: canary in config"; fail=1; fi
# (d) the inbox session token is a human credential: it must never reach a surface the
# model reads — MCP tool results, the audit log, or any other CLI output.
if grep -q "$TOKEN" "$OUT/mcp.txt"; then echo "LEAK: session token in MCP tool output"; fail=1; fi
if grep -q "$TOKEN" "$OUT/audit.txt"; then echo "LEAK: session token in the audit log"; fail=1; fi
if grep -rl "$TOKEN" "$OUT"; then echo "LEAK: session token found in agent-facing output"; fail=1; fi
if strings "$TOKENSTASH_HOME/tokenstash.db"* | grep -q "$TOKEN"; then echo "LEAK: session token in database"; fail=1; fi
if strings "$TOKENSTASH_HOME/tokenstash.db"* | grep -q "$CANARY"; then echo "LEAK: canary in database"; fail=1; fi
# env_file is configuration, not a trusted path: an absolute value would put the secret
# outside the project, where neither .gitignore nor the tracked-file check can protect it.
ESCAPE_DIR="$(mktemp -d)"; ESCAPE="$ESCAPE_DIR/ESCAPE-TARGET.env"
cp "$TOKENSTASH_HOME/config.toml" "$OUT/config.before-escape"
sed -i.bak -e "s|^env_file = .*|env_file = \"$ESCAPE\"|" "$TOKENSTASH_HOME/config.toml"
rc=0; "$TS" need OPENAI_API_KEY --agent ci >"$OUT/escape.txt" 2>&1 || rc=$?
cp "$OUT/config.before-escape" "$TOKENSTASH_HOME/config.toml"
if [ -e "$ESCAPE" ]; then echo "LEAK: absolute env_file wrote a secret outside the project"; fail=1; fi
if [ $rc -eq 0 ]; then echo "an escaping env_file must fail, not inject (got exit 0)"; fail=1; fi
grep -q "relative path inside the project" "$OUT/escape.txt" || { echo "escaping env_file must say why it was refused"; fail=1; }
rm -rf "$ESCAPE_DIR"
# exit-code contract
rc=0; "$TS" need OPENAI_API_KEY --agent ci >/dev/null 2>&1 || rc=$?; [ $rc -eq 0 ] || { echo "hit should exit 0 (got $rc)"; fail=1; }
rc=0; "$TS" need NEVER_SEEN_KEY --agent ci >/dev/null 2>&1 || rc=$?; [ $rc -eq 10 ] || { echo "miss should exit 10 (got $rc)"; fail=1; }
# the authenticated inbox page must not contain the value either
curl -fs -b "$JAR" "http://127.0.0.1:$PORT/" >"$WEB/inbox-index.html" 2>/dev/null || true
if grep -q "$CANARY" "$WEB/inbox-index.html"; then echo "LEAK: canary in inbox page"; fail=1; fi
if grep -rl "$GOOD" "$OUT" "$WEB"; then echo "LEAK: the value answered through the inbox appeared in output"; fail=1; fi
# The user kernel keyring is the one store a temp TOKENSTASH_HOME cannot isolate: check
# that nothing tokenstash owns there carries this run's canary. Values are piped straight
# into grep and never printed.
if command -v keyctl >/dev/null 2>&1; then
  for kid in $(keyctl list @u 2>/dev/null | awk -F: '/tokenstash/ { gsub(/ /, "", $1); print $1 }'); do
    if keyctl pipe "$kid" 2>/dev/null | grep -q "LEAKCANARY"; then echo "LEAK: canary in the user kernel keyring (key $kid)"; fail=1; fi
  done
fi

# ── an unverified listener on the inbox port must never be handed the token ───────────────
# Last, because it takes the inbox down for the rest of the run.
# Ownership is proved with /verify before any surface emits ?t=. When a process squats the
# port, every human-facing surface has to refuse: no token in a URL, no browser opened, no
# notification pointing there. Warning and carrying on would hand the squatter the session
# credential it needs to impersonate the inbox for the next paste.
kill "$INBOX_PID" 2>/dev/null || true
wait "$INBOX_PID" 2>/dev/null || true
cat > "$WEB/squat.py" <<'PY'
# A plain HTTP listener that answers everything with 200 "hi". It does not know the token, so
# it cannot answer /verify — which is exactly what the ownership proof is for.
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', int(sys.argv[1])))
s.listen(8)
s.settimeout(0.5)
end = time.time() + 120
while time.time() < end:
    try:
        c, _ = s.accept()
        c.recv(8192)
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi')
        c.close()
    except Exception:
        pass
PY
python3 "$WEB/squat.py" "$PORT" >/dev/null 2>&1 &
SQUAT_PID=$!   # cleanup() kills it; do not replace the trap, it also forgets the canaries
for _ in $(seq 1 50); do curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" && break; sleep 0.1; done
BROWSER=/bin/echo "$TS" open >"$OUT/squat-open.txt" 2>&1 || true
"$TS" tasks >"$OUT/squat-tasks.txt" 2>&1 || true
"$TS" doctor >"$OUT/squat-doctor.txt" 2>&1 || true
"$TS" need SQUAT_TEST_KEY --agent ci >"$OUT/squat-need.txt" 2>&1 || true
# ...and again on a pty, where the TTY-gated surfaces are in their most permissive mode
if script -qec true /dev/null >/dev/null 2>&1; then
  script -qec "$TS tasks" /dev/null >"$OUT/squat-tasks-pty.txt" 2>&1 || true
  script -qec "$TS doctor" /dev/null >"$OUT/squat-doctor-pty.txt" 2>&1 || true
  BROWSER=/bin/echo script -qec "$TS open" /dev/null >"$OUT/squat-open-pty.txt" 2>&1 || true
fi
for f in "$OUT"/squat-*.txt; do
  if grep -q "$TOKEN" "$f"; then echo "LEAK: $(basename "$f") emitted the session token while another process held the port"; fail=1; fi
  if grep -qE '\?t=' "$f"; then echo "LEAK: $(basename "$f") emitted a tokened URL for an unverified listener"; fail=1; fi
done
grep -q "held by another process" "$OUT/squat-open.txt" || { echo "FAIL: open did not say why it refused"; fail=1; }
grep -q "http://" "$OUT/squat-open.txt" && { echo "FAIL: open printed a URL for an unverified listener"; fail=1; }
for f in "$OUT"/squat-tasks*.txt "$OUT"/squat-doctor*.txt "$OUT"/squat-need.txt; do
  [ -f "$f" ] || continue
  grep -q "http://127.0.0.1:$PORT" "$f" && { echo "FAIL: $(basename "$f") linked a human to an unverified listener"; fail=1; }
done
kill "$SQUAT_PID" 2>/dev/null || true

if [ $fail -eq 0 ]; then echo "leak test passed"; fi
exit $fail
