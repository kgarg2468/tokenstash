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
