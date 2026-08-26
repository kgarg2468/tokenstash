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
- `10` at least one key is missing. The output includes an inbox link — **show it to the user**; it works as-is for pasting the key (they were also notified on the desktop). **Do not stop.** Keep working on everything that doesn't need it, then re-run the same command (or `tokenstash tasks`) to check. Use `--blocking --timeout 600` only when nothing else can proceed.
- `20` the user declined. Do not ask again. Work around it (mock the call, make the feature optional).
- `30` the task expired unanswered. Summarize what is blocked and stop.

Request all keys for a feature in one call so the human gets one card, not five.

## Non-secret human steps

```
tokenstash ask "Add TXT record for resend.dev" --url https://dash.cloudflare.com --step "DNS → Add record" --step "Type TXT, name @, value v=spf1…" --expects confirm
```

Same exit codes. `--expects text` when you need an answer back (it arrives in the task note via `tokenstash tasks --history --json`). Text answers are for questions — a region, a project id, a yes/no with context — never for secrets; those go through `need`.

## When a provider rejects a key

If an API call fails with 401 (or the provider's documented bad-key status) **and your request was well-formed** — same shape as a call that worked, auth header exactly as documented — tell tokenstash, not the user:

```
tokenstash report-bad OPENAI_API_KEY --status 401
```

Then run `need` again. A dead key is treated as missing: the user gets one card to replace it. Never ask the user to paste or rotate a key in chat. 400/404/422 from a well-formed request are not auth failures — fix the request; 403 means the key is live but lacks permission — tell the user which scope is missing. Report once; if the next `need` still injects the same key, the provider accepted it, so look at your request. If the user wants to rotate a key themselves, tell them to run `tokenstash rotate NAME` in a terminal (it refuses to run for an agent).

Usually you will not see the 401 at all: before delivering a key it has not checked in the last day, tokenstash re-checks it with the provider (one free request). A rejected key comes back from `need` as a pending **Replace** card instead of being written. Treat it like any other pending card — give the user the link, keep working — and do not report it as well.

## If MCP tools are available
Prefer the `secrets_request` / `human_request` / `task_check` / `secrets_report_invalid` tools — same semantics, structured results.

## Running things
`tokenstash run -- npm run dev` loads the env file and, if the process dies on a missing known key, files the task and restarts after the human answers.
