//! `init`: pick a stash backend, set trust roots, wire up agents.

use anyhow::Result;
use clap::Args;
use std::fs;
use std::path::{Path, PathBuf};
use tokenstash_core::Config;

pub const SKILL_MD: &str = include_str!("../../../../SKILL.md");

#[derive(Args)]
pub struct InitArgs {
    /// Also write an AGENTS.md snippet into the current project.
    #[arg(long)]
    pub project: bool,
    /// Don't touch any agent config; just set up the stash and trust roots.
    #[arg(long)]
    pub no_agents: bool,
    /// Extra trust root(s).
    #[arg(long = "trust")]
    pub trust: Vec<PathBuf>,
    /// Undo a previous `init`: restore every agent config file it changed (from the backups
    /// it took), remove the skill file and the MCP registrations. Leaves the stash alone.
    #[arg(long)]
    pub undo: bool,
}

/// What `init` did to files it does not own, so `--undo` can put them back exactly.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Manifest {
    /// (path, backup) — `backup` is `None` when the file did not exist before.
    files: Vec<(PathBuf, Option<PathBuf>)>,
    /// Directories created wholesale (the skill dir).
    dirs: Vec<PathBuf>,
    /// `claude mcp add` was run, so `claude mcp remove` undoes it.
    claude_mcp_registered: bool,
}

/// The manifest records changes to the user's GLOBAL agent configs, so it lives in one fixed
/// place — the default config dir — no matter what `TOKENSTASH_HOME` a given shell has set.
/// Otherwise an init run with a scratch home and an `--undo` run without it (or the other way
/// round) never see each other's record, and undo reports "nothing to undo" over a fully
/// wired machine. Seen in the desktop-app test.
fn manifest_path() -> PathBuf { tokenstash_core::config::default_config_dir().join("init.manifest.json") }

impl Manifest {
    /// Absent → empty. Present but unreadable/invalid → an error: silently treating a corrupt
    /// manifest as "nothing recorded" would let `--undo` say there is nothing to undo, or a
    /// re-run of `init` overwrite the only restoration points.
    fn load() -> Result<Self> {
        let p = manifest_path();
        // Older versions kept the manifest inside TOKENSTASH_HOME. If the fixed location has
        // none and the current home has one, adopt it (move, so there is one record).
        if !p.exists() {
            let legacy = tokenstash_core::config::config_dir().join("init.manifest.json");
            if legacy != p && legacy.exists() {
                if let Some(d) = p.parent() { fs::create_dir_all(d)?; }
                fs::rename(&legacy, &p).or_else(|_| fs::copy(&legacy, &p).map(|_| ()).and_then(|_| fs::remove_file(&legacy)))?;
                println!("(moved the init undo record from {} to {})", legacy.display(), p.display());
            }
        }
        match fs::read_to_string(&p) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| anyhow::anyhow!(
                "{} is unreadable ({e}). It records what a previous init changed so --undo can restore it; fix or move it, do not delete it, before running init again", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::anyhow!("reading {}: {e}", p.display())),
        }
    }
    fn save(&self) -> Result<()> {
        tokenstash_core::fsutil::write_atomic_private(&manifest_path(), &serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
    /// Back up `p`, run the mutation, and record the file ONLY if the mutation succeeded —
    /// a failed merge changed nothing, so `--undo` must not later "restore" a stale copy
    /// over work the user did afterwards. The manifest is saved after every recorded
    /// change, so a crash mid-way still leaves an undo record for what was already done.
    /// Idempotent across re-runs: the backup taken by the FIRST init is the one that
    /// matters, later runs keep it.
    fn mutate(&mut self, p: &Path, f: impl FnOnce() -> Result<()>) -> Result<()> {
        if self.files.iter().any(|(q, _)| q == p) {
            return f();
        }
        let backup = if p.exists() {
            let dir = tokenstash_core::config::default_config_dir().join("init-backups");
            fs::create_dir_all(&dir)?;
            let name = p.to_string_lossy().replace(['/', '\\'], "_");
            let b = dir.join(name);
            fs::copy(p, &b)?;
            Some(b)
        } else { None };
        // Record the intent durably BEFORE changing the file: if the manifest cannot be
        // written, the file is not touched at all, so there is never a changed file without
        // an undo record. If the change then fails, the record is withdrawn.
        self.files.push((p.to_path_buf(), backup));
        self.save()?;
        if let Err(e) = f() {
            self.files.pop();
            if let Err(e2) = self.save() {
                // The file is unchanged but its record is still on disk: say so, so the
                // user does not run --undo over later edits believing init touched it.
                return Err(e.context(format!(
                    "{} was NOT changed, but its undo record could not be withdrawn from {} ({e2}); remove that entry before running init --undo",
                    p.display(), manifest_path().display()
                )));
            }
            return Err(e);
        }
        Ok(())
    }

    fn record_dir(&mut self, d: &Path) -> Result<()> {
        if !self.dirs.iter().any(|q| q == d) {
            self.dirs.push(d.to_path_buf());
            self.save()?;
        }
        Ok(())
    }
}

fn undo() -> Result<i32> {
    let m = Manifest::load()?;
    if m.files.is_empty() && m.dirs.is_empty() && !m.claude_mcp_registered {
        println!("nothing to undo: no init manifest at {}", manifest_path().display());
        println!("(if that init ran with a custom TOKENSTASH_HOME under an older version, run --undo with the same TOKENSTASH_HOME set: the record is adopted from there)");
        return Ok(0);
    }
    // Each completed step is removed from the on-disk manifest immediately, so a retry after
    // a crash or a failed save never repeats a step already done (which would restore a
    // stale backup over an edit made in between). Whatever fails stays recorded for retry.
    let mut cur = m;
    let mut i = 0;
    while i < cur.files.len() {
        let (p, backup) = cur.files[i].clone();
        let r: Result<()> = match &backup {
            Some(b) if b.exists() => fs::copy(b, &p).map(|_| ()).map_err(Into::into),
            Some(b) => Err(anyhow::anyhow!("backup missing at {}", b.display())),
            None => match fs::remove_file(&p) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            },
        };
        match r {
            Ok(()) => {
                println!("✓ {} {}", if backup.is_some() { "restored" } else { "removed" }, p.display());
                cur.files.remove(i);
                cur.save()?;
            }
            Err(e) => { println!("! {}: {e} (kept in the manifest; re-run --undo to retry)", p.display()); i += 1; }
        }
    }
    let mut i = 0;
    while i < cur.dirs.len() {
        let d = cur.dirs[i].clone();
        match fs::remove_dir_all(&d) {
            Ok(()) => { println!("✓ removed {}", d.display()); cur.dirs.remove(i); cur.save()?; }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => { println!("✓ removed {}", d.display()); cur.dirs.remove(i); cur.save()?; }
            Err(e) => { println!("! {}: {e} (kept in the manifest)", d.display()); i += 1; }
        }
    }
    if cur.claude_mcp_registered {
        let ok = which("claude") && std::process::Command::new("claude").args(["mcp", "remove", "-s", "user", "tokenstash"])
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
        if ok { println!("✓ claude mcp remove tokenstash"); cur.claude_mcp_registered = false; cur.save()?; } else {
            println!("! could not run `claude mcp remove -s user tokenstash` (kept in the manifest; run it by hand or re-run --undo with `claude` on PATH)");
        }
    }
    let all_done = cur.files.is_empty() && cur.dirs.is_empty() && !cur.claude_mcp_registered;
    if all_done {
        let _ = fs::remove_file(manifest_path());
    }
    println!("\nThe stash, config and database were not touched (`tokenstash forget NAME` removes secrets).");
    Ok(if all_done { 0 } else { 1 })
}

pub fn init(a: InitArgs) -> Result<i32> {
    if a.undo { return undo(); }
    let mut cfg = Config::load()?;
    let fresh = !Config::exists();
    let mut manifest = Manifest::load()?;

    // 1. stash backend: probe and pin it so later calls don't re-probe
    let stash = tokenstash_core::stash::open(&cfg)?;
    let backend = stash.backend();
    if cfg.stash_backend.is_none() && backend != "insecure-file" {
        cfg.stash_backend = Some(match backend { "secret-service" | "os-keychain" => "keyring".into(), b => b.into() });
    }
    println!("✓ stash backend: {backend}{}", if backend == "keyutils" { "  (Linux kernel keyring: survives logout, not reboot; install a Secret Service like gnome-keyring for persistence)" } else { "" });

    // 2. trust roots: only what the user named, plus (on a fresh config) existing code dirs
    // under $HOME — each printed with where it came from. Never the current directory.
    let guessed: Vec<PathBuf> = if cfg.trust_roots.is_empty() { Config::default_trust_roots() } else { vec![] };
    cfg.trust_roots.extend(guessed.iter().cloned());
    let mut explicit = vec![];
    for t in &a.trust {
        let t = t.canonicalize().unwrap_or(t.clone());
        if !cfg.trust_roots.contains(&t) {
            cfg.trust_roots.push(t.clone());
        }
        explicit.push(t);
    }
    cfg.save()?;
    tokenstash_core::Db::open_default()?;
    let short = |p: &PathBuf| tokenstash_core::project::short(p);
    println!("✓ trust roots (projects here get silent injection of non-sensitive keys):");
    for r in &cfg.trust_roots {
        let how = if explicit.contains(r) { "you passed --trust" } else if guessed.contains(r) { "guessed: an existing code dir" } else { "from config" };
        println!("    {}  ({how})", short(r));
    }
    if cfg.trust_roots.is_empty() {
        println!("    (none — every project will ask once; add one with `tokenstash trust add <dir>`)");
    } else {
        println!("  remove any with `tokenstash trust rm <dir>`; elsewhere you're asked once per project");
    }

    // 3. agents
    let mut touched: Vec<PathBuf> = vec![];
    if !a.no_agents {
        let exe = std::env::current_exe()?;
        let exe_s = exe.display().to_string();
        let home = dirs::home_dir().unwrap_or_default();
        // An agent spawns the MCP server from its own environment, not this shell's. If this
        // init is running against a non-default TOKENSTASH_HOME, bake it into every
        // registration, or the server and the CLI silently use two different homes.
        let ts_home = std::env::var("TOKENSTASH_HOME").ok().filter(|h| !h.is_empty());
        if let Some(h) = &ts_home {
            println!("  (registrations carry TOKENSTASH_HOME={h} so agents use the same home as this shell)");
        }

        // Claude Code
        if home.join(".claude").is_dir() || which("claude") {
            let skill_dir = home.join(".claude/skills/tokenstash");
            let skill_md = skill_dir.join("SKILL.md");
            if !skill_dir.exists() {
                // New directory: undo removes it wholesale.
                fs::create_dir_all(&skill_dir)?;
                manifest.record_dir(&skill_dir)?;
                manifest.mutate(&skill_md, || Ok(fs::write(&skill_md, SKILL_MD)?))?;
            } else {
                // The directory was already there (a hand-written skill, an older init): back
                // the file up like any other foreign file so undo restores exactly it.
                manifest.mutate(&skill_md, || Ok(fs::write(&skill_md, SKILL_MD)?))?;
            }
            touched.push(skill_md.clone());
            // The CLI registers cleanly when present. The desktop app ships without `claude`
            // on PATH, so fall back to writing the same user-scope entry into ~/.claude.json
            // ourselves — otherwise a desktop-only user is left with a printed command.
            let claude_json = home.join(".claude.json");
            let claude_has = |name: &str| std::process::Command::new("claude").args(["mcp", "get", name])
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
            let added = if which("claude") && claude_has("tokenstash") && !manifest.claude_mcp_registered {
                // Already registered by someone else (the user, an older install): not ours
                // to remove on --undo, so no record is taken.
                if let Some(h) = &ts_home {
                    println!("! Claude Code: an existing tokenstash MCP registration was left as is; it may not use TOKENSTASH_HOME={h}. To re-register: claude mcp remove -s user tokenstash && tokenstash init");
                }
                true
            } else if which("claude") {
                // Record before registering, like every other mutation: a registration
                // with no durable record could never be undone.
                manifest.claude_mcp_registered = true;
                manifest.save()?;
                let mut args: Vec<String> = vec!["mcp".into(), "add".into(), "-s".into(), "user".into()];
                if let Some(h) = &ts_home { args.push("-e".into()); args.push(format!("TOKENSTASH_HOME={h}")); }
                args.extend(["tokenstash".into(), "--".into(), exe_s.clone(), "mcp".into()]);
                let ok = std::process::Command::new("claude")
                    .args(&args)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if !ok { manifest.claude_mcp_registered = false; manifest.save()?; }
                ok
            } else {
                match manifest.mutate(&claude_json, || merge_mcp_json_typed(&claude_json, &exe_s, true, ts_home.as_deref())) {
                    Ok(()) => { touched.push(claude_json.clone()); true }
                    Err(e) => { println!("! Claude Code: left {} untouched — {e}", claude_json.display()); false }
                }
            };
            let mcp_note = if added { ", MCP server registered".to_string() } else { format!("; register MCP with: claude mcp add -s user tokenstash -- {exe_s} mcp") };
            println!("✓ Claude Code: skill installed{mcp_note}");
        }

        // Codex
        let codex = home.join(".codex");
        if codex.is_dir() {
            let (ctoml, cagents) = (codex.join("config.toml"), codex.join("AGENTS.md"));
            match manifest.mutate(&ctoml, || merge_codex_toml(&ctoml, &exe_s, ts_home.as_deref())) {
                Ok(()) => {
                    manifest.mutate(&cagents, || append_snippet(&cagents))?;
                    touched.push(codex.join("config.toml"));
                    touched.push(codex.join("AGENTS.md"));
                    println!("✓ Codex: MCP server ({}) + usage snippet ({})", codex.join("config.toml").display(), codex.join("AGENTS.md").display());
                }
                Err(e) => println!("! Codex: left ~/.codex/config.toml untouched — {e}"),
            }
        }

        // Cursor
        let cursor = home.join(".cursor");
        if cursor.is_dir() {
            let cj = cursor.join("mcp.json");
            match manifest.mutate(&cj, || merge_mcp_json(&cj, &exe_s, ts_home.as_deref())) {
                Ok(()) => { touched.push(cursor.join("mcp.json")); println!("✓ Cursor: MCP server registered ({})", cursor.join("mcp.json").display()) }
                Err(e) => println!("! Cursor: left ~/.cursor/mcp.json untouched — {e}"),
            }
        }

        // Gemini CLI
        let gemini = home.join(".gemini");
        if gemini.is_dir() {
            let gj = gemini.join("settings.json");
            match manifest.mutate(&gj, || merge_mcp_json(&gj, &exe_s, ts_home.as_deref())) {
                Ok(()) => { touched.push(gemini.join("settings.json")); println!("✓ Gemini CLI: MCP server registered ({})", gemini.join("settings.json").display()) }
                Err(e) => println!("! Gemini CLI: left ~/.gemini/settings.json untouched — {e}"),
            }
        }
    }

    if a.project {
        let p = std::env::current_dir()?.join("AGENTS.md");
        manifest.mutate(&p, || append_snippet(&p))?;
        touched.push(p.clone());
        println!("✓ wrote tokenstash section to {}", p.display());
    }

    if !touched.is_empty() {
        println!("\nFiles outside {} that init wrote (undo with `tokenstash init --undo`):", tokenstash_core::config::config_dir().display());
        for t in &touched { println!("    {}", t.display()); }
        // MCP servers are loaded when an agent session starts; skill files are picked up
        // live. Installing from inside a running session leaves the agent told to use tools it
        // cannot see yet — the desktop-app tests hit exactly this.
        let inside = ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_SANDBOX", "CODEX_THREAD_ID", "CURSOR_TRACE_ID", "GEMINI_CLI"].iter().any(|k| std::env::var_os(k).is_some());
        if inside {
            println!("\n⚠ You are running inside an agent session. Restart it: MCP tools are loaded when a session starts, so this one cannot see tokenstash yet.");
        } else {
            println!("\nIf an agent session is already open, restart it — MCP tools are loaded when a session starts.");
        }
    }

    println!("\nKeys are re-checked with their provider before an agent gets them (once a day, one free read-only request, verify_every in config.toml) so a revoked key becomes a Replace card instead of a 401.");
    if fresh {
        println!("\nNext: from any project, run   tokenstash need OPENAI_API_KEY");
    }
    Ok(0)
}

/// Set `mcp_servers.tokenstash` in Codex's config.toml with `toml_edit`, which preserves
/// the user's comments and formatting and understands every header spelling (quoted keys,
/// whitespace, inline tables, nested subtables) — an earlier line-scanning version got a
/// steady stream of those wrong. An existing entry is replaced wholesale so the env
/// (TOKENSTASH_HOME) is current. If the file cannot be parsed it is left untouched.
fn merge_codex_toml(p: &Path, exe: &str, ts_home: Option<&str>) -> Result<()> {
    let existing = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let mut doc: toml_edit::DocumentMut = existing.parse().map_err(|e| anyhow::anyhow!("{} is not valid TOML ({e}); fix it or add the MCP server by hand", p.display()))?;
    let servers = doc.entry("mcp_servers").or_insert(toml_edit::table());
    let Some(servers) = servers.as_table_like_mut() else {
        anyhow::bail!("{}: mcp_servers is not a table; add the MCP server by hand", p.display());
    };
    let mut entry = toml_edit::Table::new();
    entry.insert("command", toml_edit::value(exe));
    let mut args = toml_edit::Array::new();
    args.push("mcp");
    entry.insert("args", toml_edit::value(args));
    if let Some(h) = ts_home {
        let mut env = toml_edit::InlineTable::new();
        env.insert("TOKENSTASH_HOME", h.into());
        entry.insert("env", toml_edit::value(env));
    }
    servers.insert("tokenstash", toml_edit::Item::Table(entry));
    let out = doc.to_string();
    // Belt and braces: the result must parse back with exactly our command.
    let back: toml::Value = toml::from_str(&out).map_err(|e| anyhow::anyhow!("refusing to write {}: result would not parse ({e})", p.display()))?;
    if back.get("mcp_servers").and_then(|m| m.get("tokenstash")).and_then(|t| t.get("command")).and_then(|c| c.as_str()) != Some(exe) {
        anyhow::bail!("refusing to write {}: could not set the tokenstash entry cleanly; edit it by hand", p.display());
    }
    if let Some(parent) = p.parent() { fs::create_dir_all(parent)?; }
    fs::write(p, out)?;
    Ok(())
}

/// Add `mcpServers.tokenstash` to a JSON config owned by another tool. If the file exists
/// but cannot be parsed as a JSON object, refuse rather than replace it.
fn merge_mcp_json(p: &Path, exe: &str, ts_home: Option<&str>) -> Result<()> {
    merge_mcp_json_typed(p, exe, false, ts_home)
}

/// Same, with `"type": "stdio"` — the shape Claude Code writes into `~/.claude.json`.
fn merge_mcp_json_typed(p: &Path, exe: &str, typed: bool, ts_home: Option<&str>) -> Result<()> {
    let mut v: serde_json::Value = match fs::read_to_string(p) {
        Ok(s) if s.trim().is_empty() => serde_json::json!({}),
        Ok(s) => serde_json::from_str(&s).map_err(|e| anyhow::anyhow!("{} is not valid JSON ({e}); fix it or add the MCP server by hand", p.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(e) => return Err(e.into()),
    };
    let root = v.as_object_mut().ok_or_else(|| anyhow::anyhow!("{} root is not a JSON object", p.display()))?;
    let servers = root.entry("mcpServers").or_insert(serde_json::json!({}));
    let m = servers.as_object_mut().ok_or_else(|| anyhow::anyhow!("{} has a non-object mcpServers", p.display()))?;
    let mut entry = if typed { serde_json::json!({ "type": "stdio", "command": exe, "args": ["mcp"] }) } else { serde_json::json!({ "command": exe, "args": ["mcp"] }) };
    if let Some(h) = ts_home {
        entry["env"] = serde_json::json!({ "TOKENSTASH_HOME": h });
    }
    m.insert("tokenstash".into(), entry);
    if let Some(parent) = p.parent() { fs::create_dir_all(parent)?; }
    fs::write(p, serde_json::to_string_pretty(&v)?)?;
    Ok(())
}

const SNIPPET_MARK: &str = "<!-- tokenstash -->";

pub fn snippet() -> String {
    format!(
        "{SNIPPET_MARK}\n## Secrets & API keys\n\nNever ask the user to paste a secret in chat. Run `tokenstash need NAME [NAME...]` (e.g. `tokenstash need OPENAI_API_KEY`).\nExit 0 = written to the project env file, continue. Exit 10 = the human was notified; keep working on other things and re-run later (or use `--blocking`).\nExit 20 = denied; do not ask again, work around it. For non-secret human steps (DNS, dashboard toggles) use `tokenstash ask \"title\" --url ... --step ...`.\n<!-- /tokenstash -->\n"
    )
}

fn append_snippet(p: &Path) -> Result<()> {
    let existing = fs::read_to_string(p).unwrap_or_default();
    if existing.contains(SNIPPET_MARK) {
        return Ok(());
    }
    let mut s = existing;
    if !s.is_empty() && !s.ends_with('\n') { s.push('\n'); }
    if !s.is_empty() { s.push('\n'); }
    s.push_str(&snippet());
    fs::write(p, s)?;
    Ok(())
}

pub fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}
