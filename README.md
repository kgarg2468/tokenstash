# tokenstash

**Your agent asks you for a key once. Never again — in any project, in any agent.**

Coding agents stall on the same line every new project:

```
Please provide: OPENAI_API_KEY= RESEND_API_KEY= STRIPE_SECRET_KEY=
```

tokenstash gives the agent one command instead. If you already have the key, it's written into the project's env file instantly. If you don't, the agent shows you a link (and you get a desktop notification); click it, follow the link to the vendor's page, paste once, and the agent resumes. **Secret values never enter the agent's context, its output, or any log.**

```
agent › tokenstash need OPENAI_API_KEY RESEND_API_KEY TAVUS_API_KEY
      ✓ OPENAI_API_KEY injected → .env.local
      ✓ RESEND_API_KEY injected → .env.local
      ⏳ TAVUS_API_KEY pending — task t_7fa2 → http://127.0.0.1:7433/t/t_7fa2
```

Works with Claude Code, Codex, Cursor, Gemini CLI, and anything that can run a shell command. Free forever, MIT, local-only, no accounts, no telemetry.

## Install

```bash
npx tokenstash init        # or: cargo install tokenstash
```

`init` picks a keychain backend, sets your trust roots (`~/code`, `~/projects`, …), registers the MCP server with the agents it finds, and installs a skill file so agents reach for it unprompted.

## How it works

```
tokenstash need NAME…   ──►  in your stash?  ──yes──►  written to .env.local, exit 0
                                   │ no
                                   ▼
                      task filed → notification → localhost inbox
                      you open the vendor page, sign up yourself, paste
                                   │
                                   ▼
                      stored in the OS keychain → injected → agent resumes
                      next project: instant, no human
```

- **You create every account.** tokenstash gets you to the right page with the right steps; it never signs up for you, never proxies an API, never reads other tools' credential stores.
- **Storage is your OS keychain** (macOS Keychain, Windows Credential Manager, Linux Secret Service; kernel keyring fallback). tokenstash keeps only names and metadata.
- **Trust roots keep the fast path fast.** Projects under your trust roots get silent injection. Elsewhere you're asked once per project. Keys tagged sensitive (live Stripe, AWS, service-role) ask once per project regardless.
- **Validated at paste time.** Known providers get a prefix check and a cheap liveness call so a typo fails now, not twenty minutes later.
- **Local secrets are generated, not requested.** `AUTH_SECRET`, `JWT_SECRET`, `SESSION_SECRET` never involve a human.

## Commands

| | |
|---|---|
| `tokenstash need NAME… [--why] [--url] [--step …] [--blocking]` | exit `0` injected · `10` pending · `20` denied · `30` expired |
| `tokenstash ask "title" [--url] [--step …] [--expects confirm\|text]` | non-secret human task (DNS, dashboard, OAuth consent) |
| `tokenstash answer [id] [--stdin] [--allow] [--deny]` | answer from the terminal instead of the inbox |
| `tokenstash tasks [--all] [--history]` · `tokenstash open` | what's waiting on you |
| `tokenstash list` · `forget NAME` · `bind NAME --identity work` | manage the stash (never shows values) |
| `tokenstash trust add\|rm\|list [dir]` | trust roots |
| `tokenstash run -- npm run dev` | zero-config shim: dies on a missing key → asks → restarts |
| `tokenstash mcp` · `tokenstash inbox` · `doctor` · `audit` · `registry` | |

## What it is not

Not a vault (use 1Password/Infisical; backends coming). Not a proxy — never in the request path. Not discovery — never reads `gh`/`aws`/Claude Code/Codex auth state. Not a sandbox: the agent can still read `.env.local`, exactly as it can today; tokenstash removes the casual leak (pasting into chat, keys echoed back), and `run --` keeps values off disk entirely.

## Security in one paragraph

Values go clipboard → keychain → env file, 0600, `.gitignore` enforced on every write. CLI output, MCP results, the SQLite index, the audit log, and errors are all value-free, and CI proves it with a canary ([`scripts/leak-test.sh`](scripts/leak-test.sh)). The inbox binds `127.0.0.1` and, because loopback is not authentication, every request needs a session: a 32-byte token arrives as `?t=` on the link you click, becomes an `HttpOnly; SameSite=Strict` cookie, and every form posts it back as a CSRF double-submit. Anything without one gets an empty 404. There are two sessions. The link the agent shows you carries the **paste-scope** token: it can answer a missing-key card and human tasks, so you click straight from the chat — but it cannot approve, so a model can request a key yet never approve its own request. The **full-scope** token (approvals too) reaches you only through channels you trigger — the desktop notification, `tokenstash open`, a terminal — and once your browser holds it, every agent link is fully capable (`inbox_links = "full"` in config hands agents the full link outright). A stash miss always involves you; a stash hit is silent only inside your trust roots for non-sensitive keys.

## Adding a provider

[`registry/providers.json`](registry/providers.json) — one JSON object: name, signup URL, steps, key prefix, optional liveness check. PRs welcome; that file is the whole product's breadth.

## License

MIT
