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

**New**
- `tokenstash workspaces list|revoke DIR|forget DIR` — which directories are paired with which keys (for a person at a terminal). Revoking never unwrites an env file.
- On-disk equivalence: a copy that brought its `.env.local` along needs no card for that delivery; it grants nothing further, and rotation never follows it.
- A directory deleted and re-created at the same path is detected (inode + birth time) and pairs again.
- Every delivery is audited with the grant that allowed it (`tokenstash audit`, `--json`).
- MCP results carry per-outcome `next` guidance; blocking calls are capped at 30 s; keys are re-verified with their provider before delivery (`verify_every`); `tokenstash export`/`import`, `export --from-env`, rotation (`rotate`, `check`, `report-bad`).

## 0.1.0

Initial release.
