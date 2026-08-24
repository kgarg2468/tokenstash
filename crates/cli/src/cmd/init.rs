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

fn manifest_path() -> PathBuf { tokenstash_core::config::config_dir().join("init.manifest.json") }

impl Manifest {
    fn load() -> Self {
        fs::read_to_string(manifest_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
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
            let dir = tokenstash_core::config::config_dir().join("init-backups");
            fs::create_dir_all(&dir)?;
            let name = p.to_string_lossy().replace(['/', '\\'], "_");
            let b = dir.join(name);
            fs::copy(p, &b)?;
            Some(b)
        } else { None };
        f()?;
        self.files.push((p.to_path_buf(), backup));
        self.save()
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
    let m = Manifest::load();
    if m.files.is_empty() && m.dirs.is_empty() && !m.claude_mcp_registered {
        println!("nothing to undo: no init manifest at {}", manifest_path().display());
        return Ok(0);
    }
    for (p, backup) in &m.files {
        match backup {
            Some(b) if b.exists() => { fs::copy(b, p)?; println!("✓ restored {}", p.display()); }
            Some(b) => println!("! backup missing for {} ({}); left as is", p.display(), b.display()),
            None => { let _ = fs::remove_file(p); println!("✓ removed {}", p.display()); }
        }
    }
    for d in &m.dirs {
        let _ = fs::remove_dir_all(d);
        println!("✓ removed {}", d.display());
    }
    if m.claude_mcp_registered && which("claude") {
        let ok = std::process::Command::new("claude").args(["mcp", "remove", "-s", "user", "tokenstash"])
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
        println!("{} claude mcp remove tokenstash", if ok { "✓" } else { "!" });
    }
    let _ = fs::remove_file(manifest_path());
    println!("\nThe stash, config and database were not touched (`tokenstash forget NAME` removes secrets).");
    Ok(0)
}

pub fn init(a: InitArgs) -> Result<i32> {
    if a.undo { return undo(); }
    let mut cfg = Config::load()?;
    let fresh = !Config::exists();
    let mut manifest = Manifest::load();

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

        // Claude Code
        if home.join(".claude").is_dir() || which("claude") {
            let skill_dir = home.join(".claude/skills/tokenstash");
            let skill_is_new = !skill_dir.exists();
            fs::create_dir_all(&skill_dir)?;
            fs::write(skill_dir.join("SKILL.md"), SKILL_MD)?;
            if skill_is_new { manifest.record_dir(&skill_dir)?; }
            touched.push(skill_dir.join("SKILL.md"));
            // The CLI registers cleanly when present. The desktop app ships without `claude`
            // on PATH, so fall back to writing the same user-scope entry into ~/.claude.json
            // ourselves — otherwise a desktop-only user is left with a printed command.
            let claude_json = home.join(".claude.json");
            let added = if which("claude") {
                let ok = std::process::Command::new("claude")
                    .args(["mcp", "add", "-s", "user", "tokenstash", "--", &exe_s, "mcp"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if ok { manifest.claude_mcp_registered = true; manifest.save()?; }
                ok
            } else {
                match manifest.mutate(&claude_json, || merge_mcp_json_typed(&claude_json, &exe_s, true)) {
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
            match manifest.mutate(&ctoml, || merge_codex_toml(&ctoml, &exe_s)) {
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
            match manifest.mutate(&cj, || merge_mcp_json(&cj, &exe_s)) {
                Ok(()) => { touched.push(cursor.join("mcp.json")); println!("✓ Cursor: MCP server registered ({})", cursor.join("mcp.json").display()) }
                Err(e) => println!("! Cursor: left ~/.cursor/mcp.json untouched — {e}"),
            }
        }

        // Gemini CLI
        let gemini = home.join(".gemini");
        if gemini.is_dir() {
            let gj = gemini.join("settings.json");
            match manifest.mutate(&gj, || merge_mcp_json(&gj, &exe_s)) {
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

    if fresh {
        println!("\nNext: from any project, run   tokenstash need OPENAI_API_KEY");
    }
    Ok(0)
}

/// Add `[mcp_servers.tokenstash]` to Codex's config.toml. The file is parsed as TOML so an
/// existing entry is detected whether it is a table header or an inline table; if the file
/// cannot be parsed it is left untouched. The entry is appended as text (not re-serialized)
/// so the user's comments and formatting survive.
fn merge_codex_toml(p: &Path, exe: &str) -> Result<()> {
    let existing = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let doc: toml::Value = if existing.trim().is_empty() {
        toml::Value::Table(Default::default())
    } else {
        toml::from_str(&existing).map_err(|e| anyhow::anyhow!("{} is not valid TOML ({e}); fix it or add the MCP server by hand", p.display()))?
    };
    if doc.get("mcp_servers").and_then(|m| m.get("tokenstash")).is_some() {
        return Ok(()); // already configured (table header or inline table)
    }
    let mut s = existing;
    if !s.is_empty() && !s.ends_with('\n') { s.push('\n'); }
    let cmd = toml::Value::String(exe.to_string()).to_string();
    s.push_str(&format!("\n[mcp_servers.tokenstash]\ncommand = {cmd}\nargs = [\"mcp\"]\n"));
    // the result must itself parse
    toml::from_str::<toml::Value>(&s).map_err(|e| anyhow::anyhow!("refusing to write {}: result would not parse ({e})", p.display()))?;
    if let Some(parent) = p.parent() { fs::create_dir_all(parent)?; }
    fs::write(p, s)?;
    Ok(())
}

/// Add `mcpServers.tokenstash` to a JSON config owned by another tool. If the file exists
/// but cannot be parsed as a JSON object, refuse rather than replace it.
fn merge_mcp_json(p: &Path, exe: &str) -> Result<()> {
    merge_mcp_json_typed(p, exe, false)
}

/// Same, with `"type": "stdio"` — the shape Claude Code writes into `~/.claude.json`.
fn merge_mcp_json_typed(p: &Path, exe: &str, typed: bool) -> Result<()> {
    let mut v: serde_json::Value = match fs::read_to_string(p) {
        Ok(s) if s.trim().is_empty() => serde_json::json!({}),
        Ok(s) => serde_json::from_str(&s).map_err(|e| anyhow::anyhow!("{} is not valid JSON ({e}); fix it or add the MCP server by hand", p.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(e) => return Err(e.into()),
    };
    let root = v.as_object_mut().ok_or_else(|| anyhow::anyhow!("{} root is not a JSON object", p.display()))?;
    let servers = root.entry("mcpServers").or_insert(serde_json::json!({}));
    let m = servers.as_object_mut().ok_or_else(|| anyhow::anyhow!("{} has a non-object mcpServers", p.display()))?;
    m.insert("tokenstash".into(), if typed { serde_json::json!({ "type": "stdio", "command": exe, "args": ["mcp"] }) } else { serde_json::json!({ "command": exe, "args": ["mcp"] }) });
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
