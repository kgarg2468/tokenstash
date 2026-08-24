#!/usr/bin/env bash
# Black-box leak test: drive the real binary with a canary secret and assert the canary never
# appears on stdout/stderr, in the database, the config, the audit log, or MCP output.
set -euo pipefail
TS="$(cd "$(dirname "${1:-target/debug/tokenstash}")" && pwd)/$(basename "${1:-target/debug/tokenstash}")"
export TOKENSTASH_HOME="$(mktemp -d)"
export TOKENSTASH_STASH=insecure-file
PROJ="$(mktemp -d)"; cd "$PROJ"; git init -q .
OUT="$(mktemp -d)"
CANARY="sk-LEAKCANARY-$(date +%s)-0123456789abcdef"

# A temp TOKENSTASH_HOME isolates the config and the database but NOT the OS credential
# store: the Linux kernel keyring is per-USER, so a canary stashed there outlives the run
# and turns up in the developer's next real session. Two defences, in this order:
#   1. pin the insecure-file backend (environment above, config below) and refuse to store
#      anything until the binary itself confirms that is the backend in use;
#   2. forget everything this run stashed, and delete the dirs holding the canary, on exit.
cleanup() {
    kill "${INBOX_PID:-}" 2>/dev/null || true
    cd / || true
    # every secret the isolated stash knows about is a canary this run created
    "$TS" list 2>/dev/null | awk '$1 != "NAME" && $1 ~ /^[A-Z][A-Z0-9_]*$/ { print $1, $2 }' \
        | while read -r n i; do "$TS" forget "$n" --identity "$i" >/dev/null 2>&1 || true; done
    rm -rf "$TOKENSTASH_HOME" "$PROJ" || true
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
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break; sleep 0.1; done
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

fail=0
if grep -rl "$CANARY" "$OUT"; then echo "LEAK: canary found in CLI/MCP output"; fail=1; fi
if grep -q "$CANARY" "$TOKENSTASH_HOME/config.toml" 2>/dev/null; then echo "LEAK: canary in config"; fail=1; fi
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
# inbox page must not contain the value either
curl -fs "http://127.0.0.1:$PORT/" >"$OUT/inbox-index.html" 2>/dev/null || true
if grep -q "$CANARY" "$OUT/inbox-index.html"; then echo "LEAK: canary in inbox page"; fail=1; fi
# The user kernel keyring is the one store a temp TOKENSTASH_HOME cannot isolate: check
# that nothing tokenstash owns there carries this run's canary. Values are piped straight
# into grep and never printed.
if command -v keyctl >/dev/null 2>&1; then
  for kid in $(keyctl list @u 2>/dev/null | awk -F: '/tokenstash/ { gsub(/ /, "", $1); print $1 }'); do
    if keyctl pipe "$kid" 2>/dev/null | grep -q "LEAKCANARY"; then echo "LEAK: canary in the user kernel keyring (key $kid)"; fail=1; fi
  done
fi
if [ $fail -eq 0 ]; then echo "leak test passed"; fi
exit $fail
