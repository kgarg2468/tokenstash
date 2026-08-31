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
