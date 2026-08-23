---
name: tokenstash
description: Get API keys and secrets for the current project without asking the user to paste them in chat. Use whenever code needs an env var like OPENAI_API_KEY, STRIPE_SECRET_KEY, RESEND_API_KEY, DATABASE_URL, or any credential, and for non-secret steps only a human can do (DNS records, dashboard toggles, OAuth consent screens).
---

# tokenstash

Your user keeps every API key they've ever acquired in a local stash. You never see values; you get them written into the project's env file.

## Never do this
- Never ask the user to paste a key, token, or secret into the chat.
- Never echo, print, or log a secret value, including from `.env.local`.
- Never create accounts or sign up on the user's behalf.

## Do this instead

```
tokenstash need OPENAI_API_KEY RESEND_API_KEY
```

Pass everything you know so the human's task card is precise:

```
tokenstash need TAVUS_API_KEY --why "POST /v2/videos needs auth" --url https://platform.tavus.io/api-keys --step "Sign in" --step "API Keys → Create"
```

Exit codes:
- `0`  every key is now in `.env.local` (or the configured env file). Continue.
- `10` at least one key is missing; the human has been notified on their desktop and inbox. **Do not stop.** Keep working on everything that doesn't need it, then re-run the same command (or `tokenstash tasks`) to check. Use `--blocking --timeout 600` only when nothing else can proceed.
- `20` the user declined. Do not ask again. Work around it (mock the call, make the feature optional).
- `30` the task expired unanswered. Summarize what is blocked and stop.

Request all keys for a feature in one call so the human gets one card, not five.

## Non-secret human steps

```
tokenstash ask "Add TXT record for resend.dev" --url https://dash.cloudflare.com --step "DNS → Add record" --step "Type TXT, name @, value v=spf1…" --expects confirm
```

Same exit codes. `--expects text` when you need an answer back (it arrives in the task note via `tokenstash tasks --history --json`).

## If MCP tools are available
Prefer the `secrets_request` / `human_request` / `task_check` tools — same semantics, structured results.

## Running things
`tokenstash run -- npm run dev` loads the env file and, if the process dies on a missing known key, files the task and restarts after the human answers.
