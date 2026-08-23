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

"$TS" init --no-agents --trust "$PROJ" >"$OUT/init.txt" 2>&1 || true
# Own the inbox for this run: a dedicated port, started by us, killed by PID. Never touch
# whatever real inbox the developer may have running.
PORT=$(( 20000 + RANDOM % 20000 ))
sed -i.bak -e "s/^inbox_port = .*/inbox_port = $PORT/" -e "s/^notifications = .*/notifications = false/" "$TOKENSTASH_HOME/config.toml"
"$TS" inbox --port "$PORT" --keep >"$OUT/inbox.txt" 2>&1 &
INBOX_PID=$!
trap 'kill "$INBOX_PID" 2>/dev/null || true' EXIT
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
SESSION_COOKIE="$INHERITED-cookie" "$TS" run -- "$PROJ/echo3.sh" >"$OUT/run4.txt" 2>&1 || true
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

# the env file is the ONE place the value is allowed to be
grep -q "OPENAI_API_KEY=$CANARY" "$PROJ/.env.local"
grep -q "^.env.local$" "$PROJ/.gitignore"

fail=0
if grep -rl "$CANARY" "$OUT"; then echo "LEAK: canary found in CLI/MCP output"; fail=1; fi
if grep -q "$CANARY" "$TOKENSTASH_HOME/config.toml" 2>/dev/null; then echo "LEAK: canary in config"; fail=1; fi
if strings "$TOKENSTASH_HOME/tokenstash.db"* | grep -q "$CANARY"; then echo "LEAK: canary in database"; fail=1; fi
# exit-code contract
rc=0; "$TS" need OPENAI_API_KEY --agent ci >/dev/null 2>&1 || rc=$?; [ $rc -eq 0 ] || { echo "hit should exit 0 (got $rc)"; fail=1; }
rc=0; "$TS" need NEVER_SEEN_KEY --agent ci >/dev/null 2>&1 || rc=$?; [ $rc -eq 10 ] || { echo "miss should exit 10 (got $rc)"; fail=1; }
# inbox page must not contain the value either
curl -fs "http://127.0.0.1:$PORT/" >"$OUT/inbox-index.html" 2>/dev/null || true
if grep -q "$CANARY" "$OUT/inbox-index.html"; then echo "LEAK: canary in inbox page"; fail=1; fi
if [ $fail -eq 0 ]; then echo "leak test passed"; fi
exit $fail
