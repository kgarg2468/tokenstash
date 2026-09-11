<h1 align="center">tokenstash</h1>

<p align="center">
  <strong>Paste a key once. Approve each directory. Keep secrets out of status output.</strong>
</p>

<p align="center">
  A local credential broker for coding agents. When your agent needs an API key, it asks tokenstash instead of asking you to paste it into the chat. The key goes into your project's env file; the agent only hears that it's there.
</p>

<p align="center">
  <a href="https://github.com/kgarg2468/tokenstash/releases/latest"><strong>Download</strong></a> ·
  <a href="SECURITY.md"><strong>Security</strong></a> ·
  <a href="CHANGELOG.md"><strong>Changelog</strong></a>
</p>

<p align="center">
  <a href="https://github.com/kgarg2468/tokenstash/actions/workflows/ci.yml"><img alt="Tests" src="https://github.com/kgarg2468/tokenstash/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="MIT" src="https://img.shields.io/badge/License-MIT-BF6A2B?style=flat-square">
  <img alt="macOS and Linux" src="https://img.shields.io/badge/macOS_·_Linux-2D2A26?style=flat-square">
  <img alt="MCP" src="https://img.shields.io/badge/MCP-server-2D2A26?style=flat-square">
  <img alt="No telemetry" src="https://img.shields.io/badge/Telemetry-none-BF6A2B?style=flat-square">
</p>

<p align="center">
  <img src="docs/assets/before-after.svg" alt="Without tokenstash, the agent stops and asks you to paste keys into the chat. With tokenstash, the agent runs one command: keys you have land in .env.local, and a key you don't have gets a link." width="880">
</p>

## Install

```bash
brew install kgarg2468/tokenstash/tokenstash
# or
npm install -g tokenstash
# or
uv tool install tokenstash
```

Then, once:

```bash
tokenstash init
```

`init` picks your OS keychain and connects tokenstash to the agents it finds: Claude Code, Codex, Cursor and Gemini CLI. macOS and Linux; Windows is not supported yet.

<details>
<summary><strong>Other ways to install</strong></summary>

```bash
bun add -g tokenstash
pnpm add -g tokenstash
pipx install tokenstash
cargo install --locked --git https://github.com/kgarg2468/tokenstash tokenstash
```

Prebuilt binaries for macOS (Apple Silicon, Intel) and Linux (x64, arm64; static, any distribution) are on the [latest release](https://github.com/kgarg2468/tokenstash/releases/latest), with sha256 files and a build attestation you can check with `gh attestation verify tokenstash-<platform>.tar.gz --repo kgarg2468/tokenstash`. The npm and PyPI packages carry the same binary and run no install scripts.

</details>

## How it works

<p align="center">
  <img src="docs/assets/how-it-works.svg" alt="The agent runs tokenstash need. If the key is in your stash and this folder is approved, it is written to .env.local. If not, you get a notification and a link to a page on localhost, you paste the key once, it goes to your OS keychain, and then into .env.local." width="880">
</p>

When the agent needs a key, it runs `tokenstash need OPENAI_API_KEY` (or calls the same thing over MCP). If you have the key and this folder is approved, it's written to `.env.local` and the agent carries on. If you don't, you get a desktop notification and a link to a page tokenstash serves on localhost, with the provider's signup link and the steps. You paste the key there once; it goes to your OS keychain, and every later project can get it from there.

<p align="center">
  <img src="docs/assets/pairing.svg" alt="One key, several folders. The folder where you pasted it has it. The first time another folder asks, you approve it once on a page on localhost, and it is quiet after that. A sensitive key asks for each folder." width="880">
</p>

- **Every folder is approved once.** The first time a folder asks for keys you already have, a page on localhost shows exactly which keys would go into which file. Approve it and that folder is silent from then on.
- **Sensitive keys ask every time a new folder wants them.** Live Stripe keys, AWS credentials, deploy and package-registry tokens, and any key tokenstash doesn't recognise, get their own approval per folder.
- **Local secrets are generated, not asked for.** `AUTH_SECRET`, `JWT_SECRET`, `SESSION_SECRET` and similar are created by tokenstash, one per folder.
- **Keys are re-checked with the provider** before delivery when a check is due, so a dead key becomes a "replace this" prompt instead of a failed request.

## Where your key goes

<p align="center">
  <img src="docs/assets/key-path.svg" alt="You paste the key on a page on localhost. It is stored in your OS keychain and written to the project's .env.local, which your app reads. The agent only receives a status line such as: OPENAI_API_KEY written to .env.local. Nothing goes into the chat." width="880">
</p>

The value goes from the page you paste it on, to your OS keychain, to the project's `.env.local` (mode `0600`, and added to `.gitignore`). The agent gets back an exit code and a line like `✓ OPENAI_API_KEY → .env.local`, never the value, so the key doesn't end up in the chat, in a summary, or in the conversation history your agent's provider keeps. [`scripts/leak-test.sh`](scripts/leak-test.sh) runs the real binary with a canary key on every commit and fails if it shows up anywhere the agent can see.

**It's not a sandbox.** An agent with a shell in an approved folder can still read `.env.local`, just as it could without tokenstash. What goes away is the casual leak: the key pasted into chat or echoed back in a summary. The full list of what it does and doesn't protect is in [SECURITY.md](SECURITY.md).

## Using it

After `tokenstash init`, the agents it connected ask on their own. You can also run it yourself:

```bash
tokenstash need OPENAI_API_KEY RESEND_API_KEY   # write keys you have, ask for the rest
tokenstash run -- npm run dev                   # restart a program once a key it needs arrives
tokenstash open                                 # the inbox: everything waiting on you
tokenstash doctor                               # check the setup
```

## Uninstall

```bash
tokenstash init --undo           # take tokenstash back out of every agent it was added to
brew uninstall tokenstash        # or: npm uninstall -g tokenstash · uv tool uninstall tokenstash · pipx uninstall tokenstash
```

<details>
<summary><strong>Remove stored keys and all data too</strong></summary>

`tokenstash list` shows the names of your stored keys and `tokenstash forget NAME` removes one from the keychain. Run those before uninstalling. Then delete the config directory: `~/.config/tokenstash` on Linux, `~/Library/Application Support/tokenstash` on macOS (or wherever `TOKENSTASH_HOME` points). Keys already written into projects' `.env.local` files stay there until you delete them.

</details>

## More

<details>
<summary><strong>All commands</strong></summary>

| Command | What it does |
| --- | --- |
| `tokenstash need NAME… [--blocking]` | Write keys to the env file, or ask for them. Exit `0` written · `10` waiting on you · `20` denied · `30` expired · `1` error |
| `tokenstash ask "title" [--url] [--step …]` | Ask you to do something only a person can do (a DNS record, a dashboard toggle, an OAuth consent screen) |
| `tokenstash open` · `tasks` · `answer [id]` | See what's waiting on you and answer it, in the inbox or from the terminal |
| `tokenstash list` · `forget NAME` · `rotate NAME` | Manage stored keys (never shows values) |
| `tokenstash check` · `report-bad NAME` | Check keys with their providers; tell tokenstash a provider rejected one |
| `tokenstash workspaces [list\|revoke DIR]` | Which folders are approved for which keys; take a folder's approvals away |
| `tokenstash export` · `import` | Move your stash to another machine in a passphrase-encrypted bundle |
| `tokenstash run -- <command>` | Run a program; if it dies on a missing key, ask for it and restart |
| `tokenstash init [--undo]` · `doctor` · `audit` | Set up or remove the agent connections; check the setup; see every delivery |

Commands that widen what an agent can reach (`answer --allow`, `open`, `list`, `forget`, `workspaces`, `export`, `import`) only run for a person at a terminal.

Agents that speak MCP get six tools: `secrets_request`, `secrets_list`, `secrets_report_invalid`, `human_request`, `task_check` and `task_list`. The MCP server only acts for the folder your agent opened.

</details>

<details>
<summary><strong>Configuration</strong></summary>

`config.toml` lives in `~/.config/tokenstash/` on Linux and `~/Library/Application Support/tokenstash/` on macOS, or wherever `TOKENSTASH_HOME` points. Every setting is optional.

| Setting | Default | |
| --- | --- | --- |
| `env_file` | `.env.local` | the file keys are written to, relative to the project root |
| `inbox_port` | `7433` | the localhost port the inbox uses |
| `task_ttl_hours` | `24` | how long a request stays open, and how long a denial is remembered |
| `stash_backend` | `auto` | `keyring` (OS keychain), `keyutils` (Linux kernel keyring; cleared on reboot), `insecure-file` (plaintext, for CI only) |
| `notifications` | `true` | desktop notifications |
| `verify_every` | `24h` | how often a key is re-checked with its provider: `<n>h`, `<n>m`, `always` or `never` |

The project is the git checkout you're in, so in a monorepo `apps/web` and `apps/api` share one `.env.local` at the repo root. A folder that isn't a checkout is its own project.

**Over SSH or in a container:** the inbox runs on the remote machine's localhost, so forward port 7433, or answer from the terminal with `tokenstash answer`. In a container without a keychain, set `TOKENSTASH_STASH=insecure-file` (plaintext) or run tokenstash on the host.

</details>

<details>
<summary><strong>Security details</strong></summary>

- **The value never comes back to the agent.** `need` and the MCP tools return a status, not the key. `tokenstash run --` is the exception by nature: it passes the program's own output through, with best-effort redaction of stored values.
- **The link an agent prints opens one request.** It can answer or decline that request and nothing else. Approving a folder needs the full inbox, which only reaches you through the desktop notification or `tokenstash open`.
- **Nothing is written into your home folder, `/`, `/tmp`, or tool and credential folders** (`~/.ssh`, `~/.aws`, `~/.claude`, …).
- **"A person at a terminal" is a heuristic.** An agent that fakes a terminal, or a process reading your keychain as you, is outside what tokenstash can stop. It guards the line between the agent's tools and you, not between programs running as you.

What's in scope, what isn't, and how to report a problem: [SECURITY.md](SECURITY.md).

</details>

<details>
<summary><strong>What it isn't</strong></summary>

Not a vault: for that, use 1Password or Infisical. Not a proxy: tokenstash is never in the path of your API requests. Not discovery: it never reads `gh`, `aws`, Claude Code or Codex credentials. Not a sandbox: see [Where your key goes](#where-your-key-goes).

</details>

<details>
<summary><strong>Adding a provider</strong></summary>

[`crates/core/registry/providers.json`](crates/core/registry/providers.json) has one entry per key: its name, the provider, the signup page, the steps, the key's format, and an optional liveness check. Pull requests welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) and the [registry verification record](docs/registry-verification.md). How well agents actually follow tokenstash's instructions is measured in [docs/agent-conformance.md](docs/agent-conformance.md).

</details>

## License

MIT
