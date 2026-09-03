# Changelog

## 0.2.0 — trust v2: directories pair once

**Breaking**
- Trust roots are retired. Nothing is trusted by folder: the first time a directory asks for stored keys you get one pairing card (Allow these / Allow these + any non-sensitive key here / Deny). `tokenstash trust add|list` print a notice; `trust rm` tidies old config; `init --trust` is accepted and ignored.
- `tokenstash need` and `tokenstash ask` lost `--project`: the directory you run them in is the project (`tasks`/`audit` keep it).
- The MCP tools lost their `project` argument. The server binds one directory at startup (the one your agent opened, or its cwd) and refuses to act for any other; it refuses to serve from `/`, your home, tool/credential directories, shared temp dirs or the directory holding the stash.
- `secrets_list` (MCP) lists only keys this directory already received or was granted.
- Keys the registry does not know are treated like sensitive keys: their own card per directory; no broad grant covers them.

**Migration** (automatic on first run)
- Per-project approvals become grants for directories that still exist and were not re-created since the approval; bindings follow. Old tables are left in place, so a 0.1 binary can still open the database.
- A project that was silent only because of a trust root shows one pairing card — unless its `.env.local` already holds the same value (non-sensitive registry keys; the file must be yours, untracked and not a symlink).

**Hardening** (pre-release audit — 14 independent reviews of the code and the tests)
- `tokenstash answer --allow` / `--allow-broad` now requires a person at a terminal, like `rotate`, `check`, `bind`, `workspaces`, `export` and `import`. An agent with a shell could otherwise read the card id from `tasks --json` and approve its own request. Denying is still open to anyone: it can only close the agent's own card.
- A card's text and link are the agent's, so they are treated as untrusted input: control, bidi and zero-width characters are stripped, the text is capped, and a link is stored only if it is `http(s)` — a `javascript:` link would have run in the inbox's own origin when clicked. For a key the registry knows, the provider's link wins over the agent's, so a card cannot point "Open …" at a lookalike page. Inbox pages carry a restrictive `Content-Security-Policy` and `Referrer-Policy: no-referrer`.
- **Generated secrets are per project.** `JWT_SECRET`, `AUTH_SECRET`, `SESSION_SECRET`, `NEXTAUTH_SECRET` and `ENCRYPTION_KEY` were stored once per identity and shared by every project that asked, so a directory with a broad grant could receive another application's signing key. Each directory now generates its own (identity `<dir>-<hash>`); values already stored are untouched.
- A generated secret's identity is never the caller's to choose: `identity: "default"` on `JWT_SECRET` from one project could hit the value an older tokenstash stored for another and, under a broad grant, deliver it without a card. A placeholder already in the env file (`changeme`) is not adopted, and approving a `run` card for a generatable name keeps the value the env file holds instead of minting a new one.
- A denied pairing or sensitive card is honoured on every path: a broad grant given later (allow-broad on another card) used to deliver the denied key silently.
- `tokenstash open` is human-only: it printed the full-scope inbox link to a pipe, which is an agent's context. `forget`, `list`, `audit`, `tasks --all` and `need --force` are human-only too; `answer` acts on another directory's card only for a person; `init` sets up the stash for anyone but registers itself as the agents' MCP server only for a person.
- A paste that other directories would receive — a Replace card, or a key they hold a grant for — needs the full inbox session or a person at the terminal. Without that, an agent in a hostile checkout could `report-bad` → `need` → `answer --stdin` its own value into every project holding the key. Closing an approval card from the paste-scope link needs the full session for the same reason.
- A non-default `TOKENSTASH_HOME` gets its own keyring namespace, so re-homing tokenstash into a directory the caller controls finds an empty stash there, not the real keys under a database it can approve against. The default home is unchanged.
- The directory name is treated as the agent's input on approval cards (control and bidi characters stripped), `TOKENSTASH_AGENT` is filtered wherever it is read, an agent-supplied `pattern` never overrides the registry's and must compile, a deny note that looks like a credential is refused, and `human_request.expects` is validated.
- A FIFO at the env file or a `.gitignore` no longer hangs `need` or the MCP server; every read of those files checks for a regular file first. An indented `NAME=` line is now seen by every reader and replaced rather than duplicated. A `run` child never loads a symlinked env file.
- Bundles accept lowercase names and multi-line (PEM) values — the rules `need` already had — so an export is importable on the next machine.
- One desktop notification per card (`need`, `ask` and the MCP tools alike): a polling agent used to re-notify on every call.
- `need --timeout` / `ask --timeout` without `--blocking` is now an error instead of being silently ignored. `tokenstash inbox` exits 1 when it cannot bind for a reason other than "already running". `doctor` reports a Gemini CLI registration. The `/health` and `/api/tasks` inbox routes, which nothing called, are gone.
- `bind NAME --identity` no longer applies to generatable names: their identity is always the directory's own.
- The crates build on macOS and Linux only; the Windows keyring dependency and the non-unix stubs are gone (the core never compiled there). `tokenstash-core` also lost `Db.conn` (crate-private), `Db::open_approval_task`, `Db::set_task_status`, `tasks::expire`, `envfile::ignore_line_covers` and `Config::default_trust_roots` — 0.2.0 is the first crates.io release, so nothing published depends on them.
- Registry: `ALGOLIA_API_KEY`, `NEON_API_KEY`, `CLOUDINARY_URL`, `SLACK_BOT_TOKEN` and `DISCORD_BOT_TOKEN` are sensitive; `MAPBOX_ACCESS_TOKEN` is sensitive for `sk.` tokens; `DATABASE_URL` accepts `sqlite:`, `file:`, `libsql:`, `sqlserver:` and `redis:`; a `query:` probe percent-encodes the key; unknown registry fields are rejected by the registry test.
- **Nine tokens became sensitive**: `GITHUB_TOKEN`, `NPM_TOKEN`, `VERCEL_TOKEN`, `CLOUDFLARE_API_TOKEN`, `FLY_API_TOKEN`, `RAILWAY_TOKEN`, `UPSTASH_REDIS_REST_TOKEN`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_SECRET`. They can push code, publish packages, redeploy or read a database, so a broad grant no longer covers them — they get their own card per directory, as `DATABASE_URL` always did.
- A broad grant (or an on-disk match) no longer overrules a denial for that key in that directory. Generating a secret now needs the same one-time approval a delivery does when the request came from a program's output.
- Answering a card is a compare-and-set: two answers racing can no longer turn a committed denial into an approval, and the loser writes nothing.
- Env file: the read-modify-write is locked, so two concurrent `need`s cannot drop a key. Newlines in a value are escaped — a pasted PEM key used to produce a line tokenstash could not read back, which made rotation silently skip that project and leave the old key on disk. A FIFO in place of the env file is refused.
- git is invoked with every `GIT_*` variable removed from its environment: `GIT_DIR` alone used to turn a tracked env file into an untracked one. A project inside a repo tokenstash will not adopt as a write root (a dotfiles repo at `$HOME`) now gets the ignore rule in its own `.gitignore` instead of none at all. If git cannot answer whether the file is ignored, the write is refused unless our own rule is provably the only one that applies.
- Rotation reports every project it could not rewrite, including ones whose env file it could not resolve or read, and one failure no longer aborts the rest.
- Revoking a workspace clears the v1 `approvals` rows too, so a 0.1 binary cannot keep delivering from them. A database written by a newer tokenstash is refused rather than half-understood. WAL sidecar files get the database's 0600.
- MCP: the stdin reader is bounded and survives invalid UTF-8; an ambiguous task-id prefix can no longer name cards from other projects.
- Probes assert `https` (or loopback) where the key crosses the wire. A free-text answer that hides a credential mid-sentence, or is a wordless passphrase, is refused like an obvious one.
- Identities are validated, with one rule shared by `need` and `bundle` (an identity containing a dot used to export and then refuse to import).
- Release: npm and PyPI publish the binaries built in that run rather than re-downloading them from the mutable GitHub release, publish jobs dropped `contents: write`, and the first npm publish carries provenance too. New `SECURITY.md`; CI runs tests, clippy and the leak test on every PR.

**New**
- `tokenstash workspaces list|revoke DIR|forget DIR` — which directories are paired with which keys (for a person at a terminal). Revoking never unwrites an env file.
- On-disk equivalence: a copy that brought its `.env.local` along needs no card for that delivery; it grants nothing further, and rotation never follows it.
- A directory deleted and re-created at the same path is detected (inode + birth time) and pairs again.
- Every delivery is audited with the grant that allowed it (`tokenstash audit`, `--json`).
- On npm, `tokenstash` is now a launcher plus per-platform binary packages (`tokenstash-<os>-<arch>`, chosen through `optionalDependencies`); there is no install script, so bun, pnpm 10 and `--ignore-scripts` installs work. `TOKENSTASH_BINARY` still overrides.
- PyPI: `uv tool install tokenstash` / `pipx install tokenstash` — wheels are the release binaries repacked, no Python code. The Homebrew tap (`kgarg2468/tokenstash/tokenstash`) is updated by the release workflow.
- Linux binaries are static (musl) and run on any distribution (DNS goes through musl's resolver: `/etc/resolv.conf` only, no NSS/mDNS); the 0.1 builds required glibc ≥ 2.39. The crates (`tokenstash`, `tokenstash-core`) now package correctly, so `cargo install tokenstash` works once they are on crates.io.
- MCP results carry per-outcome `next` guidance; blocking calls are capped at 30 s; keys are re-verified with their provider before delivery (`verify_every`); `tokenstash export`/`import`, `export --from-env`, rotation (`rotate`, `check`, `report-bad`).

## 0.1.0

Initial release.
