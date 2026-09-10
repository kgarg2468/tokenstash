<h1 align="center">tokenstash</h1>

<p align="center">
  <strong>Paste a key once. Approve each directory. Keep secrets out of status output.</strong>
</p>

<p align="center">
  tokenstash is a local credential broker for coding agents. The agent runs one command instead of stalling on <code>Please paste your API key</code>. A key you already have is written into the project's env file once you have approved that directory; a key you don't have gets you a link and a desktop notification. What the agent gets back is an exit code and a status line, not the value.
</p>

<p align="center">
  <a href="https://github.com/kgarg2468/tokenstash/releases/latest"><strong>Download</strong></a> ·
  <a href="crates/core/registry/providers.json"><strong>Provider registry</strong></a> ·
  <a href="SECURITY.md"><strong>Security</strong></a> ·
  <a href="CHANGELOG.md"><strong>Changelog</strong></a>
</p>

<p align="center">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-2021-2D2A26?style=for-the-badge&logo=rust&logoColor=white">
  <img alt="MIT" src="https://img.shields.io/badge/License-MIT-BF6A2B?style=for-the-badge">
  <img alt="MCP" src="https://img.shields.io/badge/MCP-stdio_server-2D2A26?style=for-the-badge">
  <img alt="Keychain" src="https://img.shields.io/badge/Storage-OS_keychain-BF6A2B?style=for-the-badge">
  <img alt="Providers" src="https://img.shields.io/badge/Registry-79_providers-BF6A2B?style=for-the-badge">
  <a href="https://github.com/kgarg2468/tokenstash/actions/workflows/ci.yml"><img alt="Tests" src="https://github.com/kgarg2468/tokenstash/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Telemetry" src="https://img.shields.io/badge/Telemetry-none-BF6A2B?style=for-the-badge">
</p>

## Before and after

Without tokenstash, every new project stalls on the same line, and the key you paste lands in the chat transcript:

```
Please provide: OPENAI_API_KEY= RESEND_API_KEY= TAVUS_API_KEY=
```

With it, the agent asks tokenstash instead:

```
agent › tokenstash need OPENAI_API_KEY RESEND_API_KEY TAVUS_API_KEY
      ✓ OPENAI_API_KEY injected → .env.local
      ✓ RESEND_API_KEY injected → .env.local
      ⏳ TAVUS_API_KEY pending — task t_7fa2 → http://127.0.0.1:7433/…
```

The two keys you already had were written to `.env.local` (this directory had been approved for them). The third is new: you click the link, follow it to Tavus's own key page, paste once, and the agent resumes. The next project that needs `TAVUS_API_KEY` shows you one card naming the directory and the file; approve it and that directory is silent from then on.

## Install

macOS and Linux. Pick one:

```bash
npm install -g tokenstash          # or: bun add -g tokenstash · pnpm add -g tokenstash
brew install kgarg2468/tokenstash/tokenstash
uv tool install tokenstash         # or: pipx install tokenstash
cargo install --locked --git https://github.com/kgarg2468/tokenstash tokenstash
```

Then:

```bash
tokenstash init
```

`init` picks a keychain backend and registers the MCP server with the agents it finds (Claude Code, Codex, Cursor, Gemini CLI). Claude Code also gets a skill file and Codex an `AGENTS.md` snippet, so those two reach for it unprompted; anything that can run a shell command can use the CLI. `tokenstash init --undo` takes every registration back out.

Prebuilt binaries for macOS (arm64, x64) and Linux (x64, arm64; static, any distribution) with sha256 sidecars are attached to [the latest release](https://github.com/kgarg2468/tokenstash/releases/latest). The npm package is a launcher plus one binary package per platform (`optionalDependencies`, no install scripts). The PyPI wheels carry the same binary and no Python code. Windows is not supported yet.

## How it works

| Step | What you do | What tokenstash does |
| --- | --- | --- |
| Ask | The agent needs a key it has never seen | Files a task, sends a desktop notification, prints a localhost link for the chat that opens that one card |
| Paste | You open the vendor's page and paste once | Checks the key's format, probes the provider where the registry supports it, stores the value in the OS keychain |
| Inject | Nothing: the agent re-runs the same command | Writes the key to `.env.local`, mode `0600`, `.gitignore` enforced, exit `0` |
| Reuse | A different project, a different agent, next week | Shows one **pairing card** the first time that directory asks for stored keys: exactly which keys go into which file. **Allow these**, **Allow these + any non-sensitive key here**, or **Deny** (remembered for a day). Silent there afterwards |

- **Nothing is trusted by folder.** A paste grants one key to one directory. Keys tagged sensitive (live Stripe, AWS, service-role keys, deploy and package-registry tokens) and keys the registry does not know get their own card per directory; the broad button never covers them. A directory is recognised by its path plus a fingerprint taken when it was paired; a directory deleted and re-created at the same path pairs again when the fingerprint changes (on filesystems without birth time, inode reuse can escape detection). A paste from an agent's link is refused while another directory already holds a grant that would receive it; a grant given later can still deliver a value pasted earlier, since values carry no record of who pasted them. A copy that already carries the same value in its own untracked `.env.local` needs no card for non-sensitive registry keys. Nothing is delivered into `/`, your home, `/tmp`, tool or credential directories (`~/.ssh`, `~/.aws`, `~/.claude`, …) or the directory holding the stash itself.
- **You create every account.** tokenstash gets you to the right page with the right steps; it never signs up for you, never proxies an API, never reads another tool's credential store.
- **Local secrets are generated, not requested.** `AUTH_SECRET`, `JWT_SECRET`, `SESSION_SECRET` and friends are created by tokenstash, one per directory, and never involve a human. If two directories must share one, paste it into both.
- **Eligible keys are re-checked when due.** A key whose registry entry allows an unattended probe, unchecked for longer than `verify_every` and under no lease or backoff, gets one free, read-only request to its provider before delivery, when verification is enabled for that key and the request's probe budget permits. A dead key becomes a "Replace" card; a provider outage delivers the key unchecked. Keys without such a probe are delivered as stored.
- **The project is the git root.** `need` writes the env file at the nearest checkout you own, so in a monorepo `apps/web` and `apps/api` share `repo/.env.local`. A directory that is not a checkout is its own project.

## What it protects, and what it does not

The claim is narrow on purpose. A normal credential delivery (`need`, or the `secrets_request` MCP tool) writes the value to the env file and returns status: an exit code and a line naming the key and the file, without echoing the value. The value goes from your paste to the OS keychain to the env file. `tokenstash run --` is different: it forwards the child program's own output, with best-effort redaction of exact stored values that a program printing a key in fragments defeats. Notes you type on a card (a denial reason, a text answer) are returned to the agent as text; they are not a place to paste a credential, and the check that refuses a note that looks like one is a heuristic. [`scripts/leak-test.sh`](scripts/leak-test.sh) drives the real binary with a canary and fails the build if the canary appears on any surface it exercises; it proves those surfaces, not every path a future change could add.

What it does not do:

- **It is not a sandbox.** An agent with a shell in an approved directory can read that directory's env file. Delivery *is* that file. Processes running as your user are not isolated from each other: pairing is keyed by a directory's path and fingerprint, and says nothing about what another same-user process does there. These checks assume filesystem paths remain stable during sessions and delivery; concurrent path replacement is outside this protection. The skill file and MCP guidance tell agents to load the file with the runtime rather than read it into context, and the conformance harness checks whether they comply, but nothing enforces it. tokenstash removes the casual leak (the paste into chat, the key echoed in a summary), not the deliberate read.
- **Loopback is not authentication.** Every inbox page and task action needs a credential. The one open route, `/verify`, answers an ownership challenge with a proof key that is never placed in a URL, cookie or form and is separate from the browser session. The link an agent prints opens one card and can answer or decline that card, whatever `config.toml` says; it stays restricted even in a browser that already holds the full session, so to approve a card you open the full inbox (`tokenstash open`, or the desktop notification) and select the card there rather than reloading the scoped page. The browser session is minted fresh each time the inbox starts, so a session captured before a restart stops working. Your notification history is therefore as trusted as your terminal (`notifications = false` turns it off). A bare loopback URL carries no proof of who is listening: tokenstash's own surfaces refuse to send you to an unverified listener, but if something else holds the port when you click an old link, the page you see is theirs. Details in [SECURITY.md](SECURITY.md).
- **"Person at a terminal" is a heuristic.** Commands that widen reach (`answer --allow`, `open`, `forget`, `list`, `audit`, `workspaces`, `export`, `import`, and the agent registration in `init`) refuse unless both standard streams are a terminal and no agent marker is set. An agent that allocates a pseudo-terminal and scrubs its environment, or that reads your keychain and config as your user, is outside what tokenstash can stop. It defends the line between the agent's tools and you, not the line between processes running as you.

The full list of guarantees, what is out of scope, and how to report something: [SECURITY.md](SECURITY.md).

## Upgrading from 0.1

Existing per-project approvals become grants automatically, for directories that still exist and were not re-created since. `trust_roots` in `config.toml` stop applying, so a project that was silent only because of a root shows one pairing card (unless its `.env.local` already holds the value); `tokenstash trust rm DIR` tidies the old list. `need` and `ask` lost `--project` (the directory you run them in is the project), the MCP tools lost their `project` argument, and `tokenstash workspaces` replaces `trust`. A 0.1 binary can still open the upgraded database. Details in [CHANGELOG.md](CHANGELOG.md).

## Configuration

`config.toml` lives in `~/.config/tokenstash/` (macOS: `~/Library/Application Support/tokenstash/`), or wherever `TOKENSTASH_HOME` points. Every key is optional.

| key | default | |
| --- | --- | --- |
| `env_file` | `.env.local` | the file keys are written to, relative to the project root; one setting for every project |
| `inbox_port` | `7433` | |
| `task_ttl_hours` | `24` | how long a card stays open, and how long a denial is remembered |
| `stash_backend` | `auto` | `keyring` (OS store), `keyutils` (Linux kernel keyring: survives logout, not reboot), `insecure-file` (plaintext, 0600, warns on every run; CI only). `TOKENSTASH_STASH` overrides it |
| `notifications` | `true` | desktop notifications; they carry the full inbox session |
| `inbox_links` | `paste` | legacy; accepted and ignored. The link agents print is always scoped to one card; `full` used to make it carry the full session and now only warns. The full inbox is `tokenstash open` or the notification |
| `verify_every` | `24h` | `<n>h`, `<n>m`, `always` (still at most once a minute per key), `never` |

**No browser, no desktop?** Over SSH the inbox is on the remote's loopback: forward port 7433 and run `tokenstash open` there for the full inbox, or answer from the terminal with `tokenstash answer`. In a container with no keyring, set `TOKENSTASH_STASH=insecure-file` (plaintext) or run tokenstash on the host.

**Uninstall:** `tokenstash init --undo` removes what `init` wrote outside its own directory; `tokenstash forget NAME` removes a key from the keychain; delete the config directory for the rest.

## Commands

| | |
|---|---|
| `tokenstash need NAME… [--why] [--url] [--step …] [--blocking]` | exit `0` injected · `10` pending · `20` denied · `30` expired · `1` error. `--force` re-asks after a denial and is for a person at a terminal |
| `tokenstash ask "title" [--url] [--step …] [--expects confirm\|text]` | non-secret human task (DNS, dashboard toggle, OAuth consent) |
| `tokenstash answer [id] [--stdin] [--allow] [--deny]` | answer from the terminal instead of the inbox |
| `tokenstash tasks [--all] [--history]` · `tokenstash open` | what is waiting on you |
| `tokenstash list` · `forget NAME` · `rotate NAME` · `bind NAME --identity work` | manage the stash (never shows values); `bind` after the directory has paired |
| `tokenstash check` · `report-bad NAME --status 401` | prove keys are live; tell tokenstash when a provider rejects one |
| `tokenstash export` · `import` | passphrase-encrypted bundle, to move a stash between machines |
| `tokenstash workspaces [list\|revoke DIR\|forget DIR]` | which directories are paired with which keys; take a directory's grants away (values already written stay). For a person at a terminal |
| `tokenstash run -- npm run dev` | zero-config shim: dies on a missing registry-known key → asks → restarts. Every key a program's output asks for gets its own yes, each run, never a standing grant |
| `tokenstash init [--undo]` · `mcp` · `inbox` · `doctor` · `audit` · `registry` | |

MCP tools, for agents that speak it: `secrets_request`, `secrets_list`, `secrets_report_invalid`, `human_request`, `task_check`, `task_list`. The server binds the one directory your agent opened and refuses to act for any other.

## What it is not

Not a vault: use 1Password or Infisical; backends for them are a later step. Not a proxy: tokenstash is never in the request path, and no traffic of yours flows through it. Not discovery: it never reads `gh`, `aws`, Claude Code or Codex auth state. Not a sandbox: see above.

## Adding a provider

[`crates/core/registry/providers.json`](crates/core/registry/providers.json) has one JSON object per key: name, provider, signup URL, ordered steps, key pattern, optional liveness check. PRs welcome; that file is the whole product's breadth. See [CONTRIBUTING.md](CONTRIBUTING.md) and the verification record in [`docs/registry-verification.md`](docs/registry-verification.md), reproducible with [`scripts/verify-registry.py`](scripts/verify-registry.py). Whether agents actually follow the skill file is measured by [`docs/agent-conformance.md`](docs/agent-conformance.md).

## License

MIT
