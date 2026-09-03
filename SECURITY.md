# Security policy

tokenstash holds API keys on your machine, so a defect here has real consequences. Reports are welcome and will be answered.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: **[Report a vulnerability](https://github.com/kgarg2468/tokenstash/security/advisories/new)** (Security → Advisories on the repository). That channel is private until a fix ships.

Please don't open a public issue for anything that would let one of the guarantees below be broken.

What helps: the version (`tokenstash --version`), your OS, and the smallest sequence of commands that shows the problem. A proof of concept is welcome but not required — a clear description of the path is enough.

Expect an acknowledgement within a few days. There is no bounty; this is a personal project.

## What counts as a vulnerability

These are the guarantees. Anything that breaks one is in scope:

1. **A secret value never reaches the agent.** Not on stdout or stderr, not in an MCP tool result, not in an error message, a panic, a log line, or a desktop notification. The only place a value is written is the project's env file (and `run --`'s child process environment).
2. **The human authorises every delivery.** A key reaches a directory because a person answered a card for it, or granted that directory broadly. A denial is remembered. The control that carries this is the inbox token scope: the link an agent prints is *paste-scope* — it can answer a missing-key card for a key no other directory holds, and nothing else — and the full-scope session reaches you only through the desktop notification, `tokenstash open`, or your own terminal.
3. **Project identity is the resolved directory.** Symlinks, `..`, and a re-created directory do not let one project inherit another's grants.
4. **The env file cannot be committed.** A git-tracked env file is refused, a file the repo does not ignore is refused, and if git cannot be consulted to confirm either, the write is refused.
5. **The inbox is local-only.** It binds 127.0.0.1, validates the Host header, needs an unguessable token plus a matching CSRF field, and never renders a stored value.
6. **The only network egress is a provider liveness probe** to a URL compiled into the registry, over TLS, with redirects off. No telemetry, no accounts, no proxying of the agent's requests.

## Known limits (not vulnerabilities)

These are design boundaries, documented so you can judge them rather than discover them:

- **An agent with a shell in a paired directory can read that directory's env file.** That is what delivery means. tokenstash decides *which* keys reach *which* directory; it cannot stop a process from reading a file it has been given. Scope keys per project, and use `--identity` to keep work and personal accounts apart.
- **`tokenstash run --` redacts the child's output line by line, matching the exact value.** A program that prints a key in fragments, base64-encoded, or reversed defeats that. Redaction is a courtesy; the approval gate is the control.
- **The desktop notification carries a full-scope inbox link.** That is deliberate — it is the channel that lets you approve — but it means your OS notification history is as trusted as your terminal. Turn notifications off (`notifications = false`) if that is not true for you.
- **The human-only commands refuse when they can tell they are not talking to a person, and that check is a heuristic.** `answer --allow`, `open`, `forget`, `list`, `audit`, `tasks --all`, `need --force`, `rotate`, `check`, `bind`, `workspaces`, `export`, `import` and the agent registration in `init` require both standard streams to be a TTY and no agent environment marker (`CLAUDECODE`, `CODEX_SANDBOX`, …). An agent that scrubs its environment and allocates a pseudo-terminal looks like a person to it. It is a second lock on a door whose real lock is the token scope above — worth having, not worth trusting alone.
- **A local process running as you can read the stash.** Anything with your uid can talk to your keychain, read `~/.config/tokenstash` (including the full-scope inbox token), and run `tokenstash` itself. tokenstash defends the *agent* boundary — what the tools and links it hands a model can do — not the *user* boundary. `TOKENSTASH_HOME` and `TOKENSTASH_STASH` are read from the environment of whatever runs it; a non-default home gets a keyring namespace of its own, so re-homing does not expose the real stash, but it is not a sandbox.
- **The paste-scope session is not tied to a directory.** From the agent's link, "Can't do this" on another directory's missing-key card, or a paste into it, is possible if the agent learns that card's id (the inbox index lists open cards). The CLI refuses both for an agent; the inbox cannot tell directories apart on one token. Approving, closing an approval card, and any paste that other directories would receive need the full session either way.
- **A key the agent pastes itself is a key it could have written into its own env file.** The paste-scope link refuses a paste that would reach a directory holding a grant for that name (a Replace card, or a re-paste after `forget`); a name nobody has stored yet can still be seeded by the agent and would reach another directory only if that directory later asks for the same name under a broad grant.
- **The Linux kernel keyring (`keyutils`) does not survive a reboot.** It is chosen automatically when no Secret Service is running; `tokenstash list` still shows the names afterwards, and the next `need` asks again. Install a Secret Service (gnome-keyring, KeePassXC) for persistence.
- **The `insecure-file` stash backend stores values in plaintext** at 0600. It exists for CI and tests, warns on every use, and is never selected automatically.
