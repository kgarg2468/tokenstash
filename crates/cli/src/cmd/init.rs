//! `init`: pick a stash backend, wire up agents.
//!
//! Two agent modes. `auto` registers the MCP server and installs a skill the agent loads on
//! its own, so keys are requested whenever code needs one. `explicit` installs only a slash
//! command the person types (`/tokenstash`), which runs the CLI: nothing an agent reads
//! unprompted mentions tokenstash, so a session in which it is never typed never touches it.
//! Switching modes removes the other mode's wiring, or the agent would keep calling tokenstash
//! on its own after the person asked it not to.

use anyhow::Result;
use clap::Args;
use std::fs;
use std::path::{Path, PathBuf};
use tokenstash_core::config::AgentMode;
use tokenstash_core::Config;

pub const SKILL_MD: &str = include_str!("../../SKILL.md");

#[derive(Args)]
pub struct InitArgs {
    /// How agents reach tokenstash: `auto` (registers the MCP server; the agent asks on its own)
    /// or `explicit` (a `/tokenstash` command you type; runs the CLI; nothing automatic).
    /// Remembered in config.toml, so a later `init` without --mode keeps it.
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,
    /// Also write an AGENTS.md snippet into the current project.
    #[arg(long)]
    pub project: bool,
    /// Print the AGENTS.md snippet and exit (no files touched).
    #[arg(long)]
    pub print_snippet: bool,
    /// Print the skill file for the mode and exit (no files touched).
    #[arg(long)]
    pub print_skill: bool,
    /// Don't touch any agent config; just set up the stash.
    #[arg(long)]
    pub no_agents: bool,
    /// Retired (0.2): directories pair once instead; accepted and ignored with a notice.
    #[arg(long = "trust", hide = true)]
    pub trust: Vec<PathBuf>,
    /// Undo a previous `init`: restore every agent config file it changed (from the backups
    /// it took), remove the skill file and the MCP registrations. Leaves the stash alone.
    #[arg(long)]
    pub undo: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode { Auto, Explicit }

impl From<Mode> for AgentMode {
    fn from(m: Mode) -> Self { match m { Mode::Auto => AgentMode::Auto, Mode::Explicit => AgentMode::Explicit } }
}

/// What `init` did to files it does not own, so `--undo` can put them back exactly.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Manifest {
    /// (path, backup) — `backup` is `None` when the file did not exist before.
    files: Vec<(PathBuf, Option<PathBuf>)>,
    /// Directories created wholesale (the skill dirs).
    dirs: Vec<PathBuf>,
    /// `claude mcp add` was run, so `claude mcp remove` undoes it.
    claude_mcp_registered: bool,
    /// Where this manifest and its backups live. Not part of the record.
    #[serde(skip)]
    root: PathBuf,
}

/// The manifest records changes to the user's GLOBAL agent configs, so it lives in one fixed
/// place — the default config dir — no matter what `TOKENSTASH_HOME` a given shell has set.
/// Otherwise an init run with a scratch home and an `--undo` run without it (or the other way
/// round) never see each other's record, and undo reports "nothing to undo" over a fully
/// wired machine.
fn manifest_root() -> PathBuf { tokenstash_core::config::default_config_dir() }

impl Manifest {
    fn path(&self) -> PathBuf { self.root.join("init.manifest.json") }

    fn load() -> Result<Self> {
        let root = manifest_root();
        let p = root.join("init.manifest.json");
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
        Self::load_at(root)
    }

    /// Absent → empty. Present but unreadable/invalid → an error: silently treating a corrupt
    /// manifest as "nothing recorded" would let `--undo` say there is nothing to undo, or a
    /// re-run of `init` overwrite the only restoration points.
    fn load_at(root: PathBuf) -> Result<Self> {
        let p = root.join("init.manifest.json");
        let mut m: Self = match fs::read_to_string(&p) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| anyhow::anyhow!(
                "{} is unreadable ({e}). It records what a previous init changed so --undo can restore it; fix or move it, do not delete it, before running init again", p.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", p.display())),
        };
        m.root = root;
        Ok(m)
    }
    fn save(&self) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        tokenstash_core::fsutil::write_atomic_private(&self.path(), &serde_json::to_string_pretty(self)?)?;
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
            let dir = self.root.join("init-backups");
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
                    p.display(), self.path().display()
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

    /// Put one recorded file back the way init found it — the backup, or nothing — and drop
    /// its record. For a file the other agent mode owns when modes switch: the file is
    /// tokenstash's own (a `tokenstash.md` prompt, a skill dir), so restoring the original is
    /// the right move, unlike the shared configs where only the entry is taken out. A file
    /// that is not in the manifest is not init's to touch: `Ok(false)`.
    fn release(&mut self, p: &Path) -> Result<bool> {
        let Some(i) = self.files.iter().position(|(q, _)| q == p) else { return Ok(false) };
        let (_, backup) = self.files[i].clone();
        match &backup {
            Some(b) if b.exists() => { fs::copy(b, p)?; }
            Some(b) => anyhow::bail!("backup of {} missing at {}", p.display(), b.display()),
            None => match fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            },
        }
        self.files.remove(i);
        self.save()?;
        Ok(true)
    }

    /// Remove a directory init created wholesale and drop its record. `Ok(false)` if the
    /// directory is not init's.
    fn release_dir(&mut self, d: &Path) -> Result<bool> {
        let Some(i) = self.dirs.iter().position(|q| q == d) else { return Ok(false) };
        match fs::remove_dir_all(d) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        // A file inside that directory has its own record; it is gone with the directory.
        self.files.retain(|(p, _)| !p.starts_with(d));
        self.dirs.remove(i);
        self.save()?;
        Ok(true)
    }
}

fn undo() -> Result<i32> {
    let m = Manifest::load()?;
    undo_with(m)
}

fn undo_with(m: Manifest) -> Result<i32> {
    if m.files.is_empty() && m.dirs.is_empty() && !m.claude_mcp_registered {
        println!("nothing to undo: no init manifest at {}", m.path().display());
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
        let ok = which("claude") && claude_mcp(&["remove", "-s", "user", "tokenstash"]);
        if ok { println!("✓ claude mcp remove tokenstash"); cur.claude_mcp_registered = false; cur.save()?; } else {
            println!("! could not run `claude mcp remove -s user tokenstash` (kept in the manifest; run it by hand or re-run --undo with `claude` on PATH)");
        }
    }
    let all_done = cur.files.is_empty() && cur.dirs.is_empty() && !cur.claude_mcp_registered;
    if all_done {
        let _ = fs::remove_file(cur.path());
    }
    println!("\nThe stash, config and database were not touched (`tokenstash forget NAME` removes secrets).");
    Ok(if all_done { 0 } else { 1 })
}

fn claude_mcp(args: &[&str]) -> bool {
    std::process::Command::new("claude").arg("mcp").args(args)
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

/// The machine `init` wires: where the agents' configs are, which binary to point them at.
struct Wiring {
    home: PathBuf,
    exe: String,
    /// A non-default `TOKENSTASH_HOME`, baked into every registration.
    ts_home: Option<String>,
    /// `claude` is on PATH, so registration can go through `claude mcp` instead of the file.
    claude_cli: bool,
}

impl Wiring {
    fn claude_present(&self) -> bool { self.home.join(".claude").is_dir() || self.claude_cli }
    fn claude_skill_dir(&self) -> PathBuf { self.home.join(".claude/skills/tokenstash") }
    fn claude_json(&self) -> PathBuf { self.home.join(".claude.json") }
    fn codex(&self) -> PathBuf { self.home.join(".codex") }
    fn codex_prompt(&self) -> PathBuf { self.home.join(".codex/prompts/tokenstash.md") }
    fn cursor(&self) -> PathBuf { self.home.join(".cursor") }
    fn cursor_skill_dir(&self) -> PathBuf { self.home.join(".cursor/skills/tokenstash") }
    fn gemini(&self) -> PathBuf { self.home.join(".gemini") }
    fn gemini_command(&self) -> PathBuf { self.home.join(".gemini/commands/tokenstash.toml") }
}

/// Write a skill directory's SKILL.md, recording the directory wholesale when init creates
/// it, or just the file when the directory was already there (a hand-written skill, an older
/// init) so undo restores exactly that.
fn write_skill(manifest: &mut Manifest, dir: &Path, text: &str) -> Result<PathBuf> {
    let md = dir.join("SKILL.md");
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        manifest.record_dir(dir)?;
    }
    manifest.mutate(&md, || Ok(fs::write(&md, text)?))?;
    Ok(md)
}

/// Auto mode: MCP registrations, the auto-loading skill, the AGENTS.md snippet.
fn wire_auto(manifest: &mut Manifest, w: &Wiring) -> Result<Vec<PathBuf>> {
    let mut touched = vec![];
    if w.claude_present() {
        touched.push(write_skill(manifest, &w.claude_skill_dir(), SKILL_MD)?);
        // The CLI registers cleanly when present. The desktop app ships without `claude`
        // on PATH, so fall back to writing the same user-scope entry into ~/.claude.json
        // ourselves — otherwise a desktop-only user is left with a printed command.
        let added = if w.claude_cli && claude_mcp(&["get", "tokenstash"]) && !manifest.claude_mcp_registered {
            // Already registered by someone else (the user, an older install): not ours
            // to remove on --undo, so no record is taken.
            if let Some(h) = &w.ts_home {
                println!("! Claude Code: an existing tokenstash MCP registration was left as is; it may not use TOKENSTASH_HOME={h}. To re-register: claude mcp remove -s user tokenstash && tokenstash init");
            }
            true
        } else if w.claude_cli {
            // Record before registering, like every other mutation: a registration
            // with no durable record could never be undone.
            manifest.claude_mcp_registered = true;
            manifest.save()?;
            let mut args: Vec<String> = vec!["add".into(), "-s".into(), "user".into()];
            if let Some(h) = &w.ts_home { args.push("-e".into()); args.push(format!("TOKENSTASH_HOME={h}")); }
            args.extend(["tokenstash".into(), "--".into(), w.exe.clone(), "mcp".into()]);
            let ok = claude_mcp(&args.iter().map(String::as_str).collect::<Vec<_>>());
            if !ok { manifest.claude_mcp_registered = false; manifest.save()?; }
            ok
        } else {
            let cj = w.claude_json();
            match manifest.mutate(&cj, || merge_mcp_json_typed(&cj, &w.exe, true, w.ts_home.as_deref())) {
                Ok(()) => { touched.push(cj); true }
                Err(e) => { println!("! Claude Code: left {} untouched — {e}", cj.display()); false }
            }
        };
        let mcp_note = if added { ", MCP server registered".to_string() } else { format!("; register MCP with: claude mcp add -s user tokenstash -- {} mcp", w.exe) };
        println!("✓ Claude Code: skill installed{mcp_note}");
    }

    let codex = w.codex();
    if codex.is_dir() {
        let (ctoml, cagents) = (codex.join("config.toml"), codex.join("AGENTS.md"));
        match manifest.mutate(&ctoml, || merge_codex_toml(&ctoml, &w.exe, w.ts_home.as_deref())) {
            Ok(()) => {
                manifest.mutate(&cagents, || append_snippet(&cagents))?;
                touched.push(ctoml.clone());
                touched.push(cagents.clone());
                println!("✓ Codex: MCP server ({}) + usage snippet ({})", ctoml.display(), cagents.display());
            }
            Err(e) => println!("! Codex: left {} untouched — {e}", ctoml.display()),
        }
    }

    let cursor = w.cursor();
    if cursor.is_dir() {
        let cj = cursor.join("mcp.json");
        match manifest.mutate(&cj, || merge_mcp_json(&cj, &w.exe, w.ts_home.as_deref())) {
            Ok(()) => { touched.push(cj.clone()); println!("✓ Cursor: MCP server registered ({})", cj.display()) }
            Err(e) => println!("! Cursor: left {} untouched — {e}", cj.display()),
        }
    }

    let gemini = w.gemini();
    if gemini.is_dir() {
        let gj = gemini.join("settings.json");
        match manifest.mutate(&gj, || merge_mcp_json(&gj, &w.exe, w.ts_home.as_deref())) {
            Ok(()) => { touched.push(gj.clone()); println!("✓ Gemini CLI: MCP server registered ({})", gj.display()) }
            Err(e) => println!("! Gemini CLI: left {} untouched — {e}", gj.display()),
        }
    }
    Ok(touched)
}

/// Explicit mode: a user-invoked command per agent, running the CLI. No MCP server, no
/// snippet, nothing the agent loads on its own.
fn wire_explicit(manifest: &mut Manifest, w: &Wiring) -> Result<Vec<PathBuf>> {
    let mut touched = vec![];
    if w.claude_present() {
        touched.push(write_skill(manifest, &w.claude_skill_dir(), &skill_text(AgentMode::Explicit))?);
        println!("✓ Claude Code: /tokenstash installed (only you can invoke it)");
    }
    if w.codex().is_dir() {
        let p = w.codex_prompt();
        manifest.mutate(&p, || {
            if let Some(d) = p.parent() { fs::create_dir_all(d)?; }
            Ok(fs::write(&p, codex_prompt_text())?)
        })?;
        touched.push(p.clone());
        println!("✓ Codex: /prompts:tokenstash installed ({})", p.display());
    }
    if w.cursor().is_dir() {
        touched.push(write_skill(manifest, &w.cursor_skill_dir(), &skill_text(AgentMode::Explicit))?);
        println!("✓ Cursor: /tokenstash installed (only you can invoke it)");
    }
    if w.gemini().is_dir() {
        let p = w.gemini_command();
        manifest.mutate(&p, || {
            if let Some(d) = p.parent() { fs::create_dir_all(d)?; }
            Ok(fs::write(&p, gemini_command_text()?)?)
        })?;
        touched.push(p.clone());
        println!("✓ Gemini CLI: /tokenstash installed ({})", p.display());
    }
    Ok(touched)
}

/// Take auto mode's wiring out: every MCP registration and the AGENTS.md snippet. Only the
/// tokenstash entry leaves a shared config; the rest of the file is the user's. A registration
/// that is there but not init's (the user's own `claude mcp add`) is removed too — leaving it
/// would keep the agent calling tokenstash on its own, which is what explicit mode is against.
fn unwire_auto(manifest: &mut Manifest, w: &Wiring) -> Result<()> {
    if manifest.claude_mcp_registered && w.claude_cli && claude_mcp(&["remove", "-s", "user", "tokenstash"]) {
        manifest.claude_mcp_registered = false;
        manifest.save()?;
        println!("✓ Claude Code: MCP server removed (claude mcp remove)");
    } else if w.claude_cli && claude_mcp(&["get", "tokenstash"]) {
        if claude_mcp(&["remove", "-s", "user", "tokenstash"]) {
            manifest.claude_mcp_registered = false;
            manifest.save()?;
            println!("✓ Claude Code: MCP server removed (claude mcp remove)");
        } else {
            println!("! Claude Code: could not remove the MCP registration; run: claude mcp remove -s user tokenstash");
        }
    }
    let cj = w.claude_json();
    if json_has_server(&cj) {
        manifest.mutate(&cj, || remove_mcp_json(&cj))?;
        release_if_empty(manifest, &cj)?;
        println!("✓ Claude Code: MCP server removed from {}", cj.display());
    }
    let ctoml = w.codex().join("config.toml");
    if toml_has_server(&ctoml) {
        manifest.mutate(&ctoml, || remove_codex_toml(&ctoml))?;
        println!("✓ Codex: MCP server removed from {}", ctoml.display());
    }
    let cagents = w.codex().join("AGENTS.md");
    if fs::read_to_string(&cagents).map(|s| s.contains(SNIPPET_MARK)).unwrap_or(false) {
        manifest.mutate(&cagents, || strip_snippet(&cagents))?;
        println!("✓ Codex: usage snippet removed from {}", cagents.display());
    }
    for (name, p) in [("Cursor", w.cursor().join("mcp.json")), ("Gemini CLI", w.gemini().join("settings.json"))] {
        if json_has_server(&p) {
            manifest.mutate(&p, || remove_mcp_json(&p))?;
            release_if_empty(manifest, &p)?;
            println!("✓ {name}: MCP server removed from {}", p.display());
        }
    }
    Ok(())
}

/// A JSON config init created (no backup) that now holds nothing but an empty `mcpServers`
/// is init's own leftover: remove it rather than leave a stub in the user's home.
fn release_if_empty(manifest: &mut Manifest, p: &Path) -> Result<()> {
    let created = manifest.files.iter().any(|(q, b)| q == p && b.is_none());
    let empty = read_json(p).map(|v| v == serde_json::json!({ "mcpServers": {} })).unwrap_or(false);
    if created && empty { manifest.release(p)?; }
    Ok(())
}

/// Take explicit mode's wiring out: the prompt, the command and the Cursor skill. Each is
/// tokenstash's own file, so it goes back to what init found (usually nothing). The Claude
/// skill is not removed: auto mode rewrites it.
fn unwire_explicit(manifest: &mut Manifest, w: &Wiring) -> Result<()> {
    for (name, p) in [("Codex", w.codex_prompt()), ("Gemini CLI", w.gemini_command())] {
        if manifest.release(&p)? {
            println!("✓ {name}: /tokenstash command removed ({})", p.display());
        } else if p.exists() {
            println!("! {name}: {} was not written by init; remove it yourself if it is not yours", p.display());
        }
    }
    let d = w.cursor_skill_dir();
    if manifest.release_dir(&d)? || manifest.release(&d.join("SKILL.md"))? {
        println!("✓ Cursor: /tokenstash skill removed ({})", d.display());
    } else if d.exists() {
        println!("! Cursor: {} was not written by init; remove it yourself if it is not yours", d.display());
    }
    Ok(())
}

pub fn init(a: InitArgs) -> Result<i32> {
    if a.print_snippet { print!("{}", snippet_for(a.mode.map(Into::into).unwrap_or_default())); return Ok(0); }
    if a.print_skill { print!("{}", skill_text(a.mode.map(Into::into).unwrap_or_default())); return Ok(0); }
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

    // 2. trust: nothing is inferred and nothing is added. The first time a directory asks
    // for stored keys the human approves exactly which ones; that is the whole model.
    // The mode is remembered here too, so a later plain `init` keeps it.
    let mode: AgentMode = a.mode.map(Into::into).unwrap_or(cfg.agent_mode);
    let switched = !fresh && mode != cfg.agent_mode;
    cfg.agent_mode = mode;
    cfg.save()?;
    tokenstash_core::Db::open_default()?;
    if !a.trust.is_empty() {
        println!("! --trust is retired: directories are not trusted by folder any more. The first stored key a directory asks for shows you one card; approve it and those keys are silent there.");
    }
    if !cfg.trust_roots.is_empty() {
        println!("! trust_roots in config.toml no longer apply (retired in 0.2); `tokenstash trust rm <dir>` tidies them");
    }
    println!("✓ trust: each directory pairs once (`tokenstash workspaces` lists them)");
    println!("✓ agent mode: {}", describe_mode(mode));

    // 3. agents
    let mut touched: Vec<PathBuf> = vec![];
    // Registering points every future agent session at this binary. Run by an agent from a
    // hostile checkout (`cargo build && ./target/debug/tokenstash init`) that would be a
    // binary that hands values to the model. The stash and config are set up either way.
    let register_agents = !a.no_agents && match crate::util::require_human("init", "it registers this binary as every agent's MCP server") {
        Ok(()) => true,
        Err(e) => { println!("! {e:#}\n  Agents were not registered; the stash and config are ready. (--no-agents silences this.)"); false }
    };
    if register_agents {
        let exe = std::env::current_exe()?;
        let home = dirs::home_dir().unwrap_or_default();
        // An agent spawns the MCP server from its own environment, not this shell's. If this
        // init is running against a non-default TOKENSTASH_HOME, bake it into every
        // registration, or the server and the CLI silently use two different homes.
        let ts_home = std::env::var("TOKENSTASH_HOME").ok().filter(|h| !h.is_empty());
        if let (Some(h), AgentMode::Auto) = (&ts_home, mode) {
            println!("  (registrations carry TOKENSTASH_HOME={h} so agents use the same home as this shell)");
        }
        let w = Wiring { home, exe: exe.display().to_string(), ts_home, claude_cli: which("claude") };
        touched = wire(&mut manifest, &w, mode)?;
    }

    if a.project {
        let p = std::env::current_dir()?.join("AGENTS.md");
        manifest.mutate(&p, || append_snippet_for(&p, mode))?;
        touched.push(p.clone());
        println!("✓ wrote tokenstash section to {}", p.display());
    }

    if !touched.is_empty() {
        println!("\nFiles outside {} that init wrote (undo with `tokenstash init --undo`):", tokenstash_core::config::config_dir().display());
        for t in &touched { println!("    {}", t.display()); }
        // MCP servers are loaded when an agent session starts; skill files are picked up
        // live. Installing from inside a running session leaves the agent told to use tools it
        // cannot see yet — the desktop-app tests hit exactly this.
        let inside = tokenstash_core::project::detect_agent() != "unknown";
        if inside {
            println!("\n⚠ You are running inside an agent session. Restart it: MCP tools are loaded when a session starts, so this one cannot see tokenstash yet.");
        } else if switched {
            println!("\nRestart any open agent session: MCP tools are loaded when a session starts, so a running one keeps the old mode.");
        } else {
            println!("\nIf an agent session is already open, restart it — MCP tools are loaded when a session starts.");
        }
    }

    println!("\nKeys are re-checked with their provider before an agent gets them (once a day, one free read-only request, verify_every in config.toml) so a revoked key becomes a Replace card instead of a 401.");
    if fresh {
        match mode {
            AgentMode::Auto => println!("\nNext: from any project, run   tokenstash need OPENAI_API_KEY"),
            AgentMode::Explicit => println!("\nNext: in your agent, type   /tokenstash OPENAI_API_KEY   (Codex: /prompts:tokenstash)"),
        }
    }
    Ok(0)
}

/// Wire one mode and take the other's wiring out, in that order for auto (the skill file is
/// shared, and the rewrite must win) and the other way round for explicit (nothing automatic
/// may be left once the command is in place; the command itself never depends on it).
fn wire(manifest: &mut Manifest, w: &Wiring, mode: AgentMode) -> Result<Vec<PathBuf>> {
    match mode {
        AgentMode::Auto => {
            unwire_explicit(manifest, w)?;
            wire_auto(manifest, w)
        }
        AgentMode::Explicit => {
            unwire_auto(manifest, w)?;
            wire_explicit(manifest, w)
        }
    }
}

pub fn describe_mode(mode: AgentMode) -> &'static str {
    match mode {
        AgentMode::Auto => "auto — agents ask tokenstash on their own (MCP server + skill)",
        AgentMode::Explicit => "explicit — agents use tokenstash only when you type /tokenstash (CLI; no MCP server)",
    }
}

/// What is installed for each agent on this machine, for `doctor`: "claude-code (skill: auto)",
/// "codex (mcp, snippet)", "gemini-cli (command)". Read from the files, not the manifest, so a
/// registration made by hand shows too.
pub fn installed(home: &Path) -> Vec<String> {
    let mut out = vec![];
    let skill_mode = |dir: &Path| -> Option<&'static str> {
        let s = fs::read_to_string(dir.join("SKILL.md")).ok()?;
        Some(if frontmatter(&s).contains("disable-model-invocation: true") { "skill: explicit" } else { "skill: auto" })
    };
    let mut claude = vec![];
    if let Some(m) = skill_mode(&home.join(".claude/skills/tokenstash")) { claude.push(m); }
    if json_has_server(&home.join(".claude.json")) { claude.push("mcp"); }
    if !claude.is_empty() { out.push(format!("claude-code ({})", claude.join(", "))); }
    let mut codex = vec![];
    if toml_has_server(&home.join(".codex/config.toml")) { codex.push("mcp"); }
    if fs::read_to_string(home.join(".codex/AGENTS.md")).map(|s| s.contains(SNIPPET_MARK)).unwrap_or(false) { codex.push("snippet"); }
    if home.join(".codex/prompts/tokenstash.md").is_file() { codex.push("prompt"); }
    if !codex.is_empty() { out.push(format!("codex ({})", codex.join(", "))); }
    let mut cursor = vec![];
    if json_has_server(&home.join(".cursor/mcp.json")) { cursor.push("mcp"); }
    if let Some(m) = skill_mode(&home.join(".cursor/skills/tokenstash")) { cursor.push(m); }
    if !cursor.is_empty() { out.push(format!("cursor ({})", cursor.join(", "))); }
    let mut gemini = vec![];
    if json_has_server(&home.join(".gemini/settings.json")) { gemini.push("mcp"); }
    if home.join(".gemini/commands/tokenstash.toml").is_file() { gemini.push("command"); }
    if !gemini.is_empty() { out.push(format!("gemini-cli ({})", gemini.join(", "))); }
    out
}

/// Set `mcp_servers.tokenstash` in Codex's config.toml with `toml_edit`, which preserves
/// the user's comments and formatting and understands every header spelling (quoted keys,
/// whitespace, inline tables, nested subtables) — an earlier line-scanning version got a
/// steady stream of those wrong. An existing entry is replaced wholesale so the env
/// (TOKENSTASH_HOME) is current. If the file cannot be parsed it is left untouched.
fn merge_codex_toml(p: &Path, exe: &str, ts_home: Option<&str>) -> Result<()> {
    let mut doc = read_toml(p)?;
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

/// Take `mcp_servers.tokenstash` out of Codex's config.toml, leaving everything else as
/// written. An empty `mcp_servers` table is left in place: it is the user's line now.
fn remove_codex_toml(p: &Path) -> Result<()> {
    let mut doc = read_toml(p)?;
    if let Some(servers) = doc.get_mut("mcp_servers").and_then(|s| s.as_table_like_mut()) {
        servers.remove("tokenstash");
    }
    let out = doc.to_string();
    let back: toml::Value = toml::from_str(&out).map_err(|e| anyhow::anyhow!("refusing to write {}: result would not parse ({e})", p.display()))?;
    if back.get("mcp_servers").and_then(|m| m.get("tokenstash")).is_some() {
        anyhow::bail!("refusing to write {}: could not take the tokenstash entry out cleanly; edit it by hand", p.display());
    }
    fs::write(p, out)?;
    Ok(())
}

fn read_toml(p: &Path) -> Result<toml_edit::DocumentMut> {
    let existing = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    existing.parse().map_err(|e| anyhow::anyhow!("{} is not valid TOML ({e}); fix it or add the MCP server by hand", p.display()))
}

fn toml_has_server(p: &Path) -> bool {
    fs::read_to_string(p).ok()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .map(|d| d.get("mcp_servers").and_then(|m| m.get("tokenstash")).is_some())
        .unwrap_or(false)
}

/// Add `mcpServers.tokenstash` to a JSON config owned by another tool. If the file exists
/// but cannot be parsed as a JSON object, refuse rather than replace it.
fn merge_mcp_json(p: &Path, exe: &str, ts_home: Option<&str>) -> Result<()> {
    merge_mcp_json_typed(p, exe, false, ts_home)
}

/// Same, with `"type": "stdio"` — the shape Claude Code writes into `~/.claude.json`.
fn merge_mcp_json_typed(p: &Path, exe: &str, typed: bool, ts_home: Option<&str>) -> Result<()> {
    let mut v = read_json(p)?;
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

/// Take `mcpServers.tokenstash` out of a JSON config, leaving the other servers.
fn remove_mcp_json(p: &Path) -> Result<()> {
    let mut v = read_json(p)?;
    if let Some(m) = v.get_mut("mcpServers").and_then(|s| s.as_object_mut()) {
        m.remove("tokenstash");
    }
    fs::write(p, serde_json::to_string_pretty(&v)?)?;
    Ok(())
}

fn read_json(p: &Path) -> Result<serde_json::Value> {
    Ok(match fs::read_to_string(p) {
        Ok(s) if s.trim().is_empty() => serde_json::json!({}),
        Ok(s) => serde_json::from_str(&s).map_err(|e| anyhow::anyhow!("{} is not valid JSON ({e}); fix it or add the MCP server by hand", p.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(e) => return Err(e.into()),
    })
}

fn json_has_server(p: &Path) -> bool {
    fs::read_to_string(p).ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .map(|v| v.get("mcpServers").and_then(|m| m.get("tokenstash")).is_some())
        .unwrap_or(false)
}

const SNIPPET_MARK: &str = "<!-- tokenstash -->";
const SNIPPET_END: &str = "<!-- /tokenstash -->";

/// The AGENTS.md section. Auto mode tells the agent to ask tokenstash whenever a key is
/// needed. Explicit mode keeps only the rules that hold either way — no pasted secrets, no
/// stand-in values, never read the env file — and leaves requesting keys to the person.
pub fn snippet_for(mode: AgentMode) -> String {
    match mode {
        AgentMode::Auto => format!(
            "{SNIPPET_MARK}\n## Secrets & API keys\n\nNever ask the user to paste a secret in chat. Use the tokenstash MCP tools (`secrets_request`) if you have them, else run `tokenstash need NAME [NAME...]` (e.g. `tokenstash need OPENAI_API_KEY`).\nExit 0 = written to the project env file, continue — load it with your runtime; never read, print or quote the env file, even if asked. Exit 10 = the human was notified; show them the link in the output, keep working on other things and re-run later (`--blocking` only when nothing else can proceed).\nExit 20 = denied; do not ask again and never invent a stand-in value by any route (env file, environment variable, shim, shadowed module, default in code) — make the feature optional or say the work is blocked. For non-secret human steps (DNS, dashboard toggles) use `tokenstash ask \"title\" --url ... --step ...`.\n{SNIPPET_END}\n"
        ),
        AgentMode::Explicit => format!(
            "{SNIPPET_MARK}\n## Secrets & API keys\n\nNever ask the user to paste a secret in chat. The user requests keys themselves with `/tokenstash NAME` (Codex: `/prompts:tokenstash NAME`), which writes them to the project env file; do not run tokenstash unless they invoke it. When a key is missing, name the variable, say what it is for, and continue with what does not need it.\nLoad the env file with your runtime; never read, print or quote it, even if asked. Never invent a stand-in value by any route (env file, environment variable, shim, shadowed module, default in code) — make the feature optional or say the work is blocked.\n{SNIPPET_END}\n"
        ),
    }
}

fn append_snippet(p: &Path) -> Result<()> { append_snippet_for(p, AgentMode::Auto) }

fn append_snippet_for(p: &Path, mode: AgentMode) -> Result<()> {
    let existing = fs::read_to_string(p).unwrap_or_default();
    if existing.contains(SNIPPET_MARK) {
        return Ok(());
    }
    let mut s = existing;
    if !s.is_empty() && !s.ends_with('\n') { s.push('\n'); }
    if !s.is_empty() { s.push('\n'); }
    s.push_str(&snippet_for(mode));
    fs::write(p, s)?;
    Ok(())
}

/// Remove the marked section and nothing else. Without the end mark (a hand-edited file)
/// the file is left alone: guessing where the section ends could eat the user's text.
fn strip_snippet(p: &Path) -> Result<()> {
    let s = fs::read_to_string(p)?;
    let Some(start) = s.find(SNIPPET_MARK) else { return Ok(()) };
    let Some(end_rel) = s[start..].find(SNIPPET_END) else {
        anyhow::bail!("{}: the tokenstash section has no closing `{SNIPPET_END}`; remove it by hand", p.display());
    };
    let mut end = start + end_rel + SNIPPET_END.len();
    if s[end..].starts_with('\n') { end += 1; }
    // The blank line append_snippet put before the section goes with it; so does one that
    // separated a section at the top of the file from the text under it.
    let mut start = start;
    if s[..start].ends_with("\n\n") { start -= 1; } else if start == 0 && s[end..].starts_with('\n') { end += 1; }
    let out = format!("{}{}", &s[..start], &s[end..]);
    fs::write(p, out)?;
    Ok(())
}

fn frontmatter(skill: &str) -> &str {
    skill.strip_prefix("---\n").and_then(|rest| rest.find("\n---\n").map(|i| &rest[..i])).unwrap_or("")
}

fn body(skill: &str) -> &str {
    skill.strip_prefix("---\n").and_then(|rest| rest.find("\n---\n").map(|i| &rest[i + 5..])).unwrap_or(skill)
}

const MCP_SECTION: &str = "## If MCP tools are available";

/// One set of rules, two ways in. Auto mode's skill is `SKILL.md` as shipped. Explicit mode's
/// is derived from it: only the person can invoke it, the arguments name the keys, and the
/// MCP section goes (there is no server in that mode). Everything else — never paste, never
/// read the env file, exit codes, no stand-in values, report-bad — is the same text.
pub fn skill_text(mode: AgentMode) -> String {
    match mode {
        AgentMode::Auto => SKILL_MD.to_string(),
        AgentMode::Explicit => format!(
            "---\nname: tokenstash\ndescription: Get API keys and secrets for this project through tokenstash, without pasting them in chat. /tokenstash NAME [NAME...] requests those keys; bare /tokenstash requests whatever the current task needs.\ndisable-model-invocation: true\n---\n\n{}",
            explicit_body("$ARGUMENTS")
        ),
    }
}

/// The explicit-mode rules with the harness's own placeholder for what the user typed after
/// the command: `$ARGUMENTS` for Claude Code, Cursor and Codex, `{{args}}` for Gemini CLI.
pub fn explicit_body(args: &str) -> String {
    let b = body(SKILL_MD);
    let b = match b.find(MCP_SECTION) {
        Some(i) => {
            let after = &b[i + MCP_SECTION.len()..];
            let rest = after.find("\n## ").map(|j| &after[j + 1..]).unwrap_or("");
            format!("{}{}", &b[..i], rest)
        }
        None => b.to_string(),
    };
    let intro = format!(
        "# tokenstash\n\nThe user invoked this themselves: `/tokenstash {args}`. The names after the command are the keys to request; with none, request the keys the current task needs. Nothing else in this session asks tokenstash on its own, so from here on every key this task turns out to need goes through `tokenstash need`, never through the chat.\n"
    );
    b.replacen("# tokenstash\n", &intro, 1).trim_start_matches('\n').to_string()
}

/// Codex custom prompt: `~/.codex/prompts/tokenstash.md`, invoked as `/prompts:tokenstash`.
/// `$ARGUMENTS` is Codex's own placeholder; a literal `$` would need `$$`, and the body has none.
pub fn codex_prompt_text() -> String {
    format!(
        "---\ndescription: Get API keys for this project through tokenstash (never pasted in chat)\nargument-hint: \"[NAME ...]\"\n---\n\n{}",
        explicit_body("$ARGUMENTS").replace("`/tokenstash $ARGUMENTS`", "`/prompts:tokenstash $ARGUMENTS`")
    )
}

/// Gemini CLI custom command: `~/.gemini/commands/tokenstash.toml`, invoked as `/tokenstash`.
pub fn gemini_command_text() -> Result<String> {
    #[derive(serde::Serialize)]
    struct Command { description: &'static str, prompt: String }
    Ok(toml::to_string(&Command {
        description: "Get API keys for this project through tokenstash (never pasted in chat)",
        prompt: explicit_body("{{args}}"),
    })?)
}

pub fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("tokenstash-init-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// A fake machine: a home with every agent's directory, and a manifest root beside it.
    fn machine(name: &str) -> (Wiring, Manifest) {
        let root = scratch(name);
        let home = root.join("home");
        for d in [".claude", ".codex", ".cursor", ".gemini"] { fs::create_dir_all(home.join(d)).unwrap(); }
        let w = Wiring { home, exe: "/opt/tokenstash".into(), ts_home: None, claude_cli: false };
        let m = Manifest::load_at(root.join("state")).unwrap();
        (w, m)
    }

    fn read(p: &Path) -> String { fs::read_to_string(p).unwrap_or_default() }

    #[test]
    fn the_explicit_skill_is_user_only_and_keeps_every_rule() {
        let auto = skill_text(AgentMode::Auto);
        let explicit = skill_text(AgentMode::Explicit);
        assert_eq!(auto, SKILL_MD);
        assert!(!frontmatter(&auto).contains("disable-model-invocation"));
        assert!(frontmatter(&explicit).contains("disable-model-invocation: true"), "{explicit}");
        assert!(frontmatter(&explicit).starts_with("name: tokenstash\n"));
        assert!(explicit.contains("`/tokenstash $ARGUMENTS`"));
        // The rules are the same text, MCP section aside.
        for rule in ["## Never do this", "Never ask the user to paste", "Never read `.env.local`", "`20` the user declined", "never invent a stand-in value", "## When a provider rejects a key", "tokenstash report-bad", "## Non-secret human steps", "## Running things"] {
            assert!(auto.contains(rule) && explicit.contains(rule), "{rule}");
        }
        assert!(auto.contains(MCP_SECTION));
        for mcp in [MCP_SECTION, "secrets_request", "task_check", "MCP"] {
            assert!(!explicit.contains(mcp), "explicit mode has no server, so nothing may point at one: {mcp}");
        }
        // Derived text is a slice of the original: nothing was lost around the cut.
        let end_of_mcp = body(SKILL_MD).find("## Running things").unwrap();
        assert!(explicit.ends_with(&body(SKILL_MD)[end_of_mcp..]));
    }

    #[test]
    fn each_harness_gets_its_own_placeholder_and_nothing_else_is_a_dollar() {
        let codex = codex_prompt_text();
        assert!(codex.starts_with("---\ndescription: "));
        assert!(codex.contains("`/prompts:tokenstash $ARGUMENTS`"));
        assert_eq!(codex.matches('$').count(), codex.matches("$ARGUMENTS").count(), "Codex expands every `$`; a stray one would need `$$`");
        let gemini = gemini_command_text().unwrap();
        let v: toml::Value = toml::from_str(&gemini).unwrap();
        let prompt = v["prompt"].as_str().unwrap();
        assert!(prompt.contains("`/tokenstash {{args}}`"));
        assert!(!prompt.contains("$ARGUMENTS"));
        assert!(v["description"].as_str().unwrap().contains("tokenstash"));
        assert_eq!(prompt, explicit_body("{{args}}"));
    }

    #[test]
    fn explicit_mode_writes_only_user_invoked_commands() {
        let (w, mut m) = machine("explicit");
        let touched = wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert_eq!(touched.len(), 4, "{touched:?}");
        assert!(read(&w.claude_skill_dir().join("SKILL.md")).contains("disable-model-invocation: true"));
        assert!(read(&w.cursor_skill_dir().join("SKILL.md")).contains("disable-model-invocation: true"));
        assert!(read(&w.codex_prompt()).contains("/prompts:tokenstash"));
        assert!(read(&w.gemini_command()).contains("{{args}}"));
        for absent in [w.claude_json(), w.codex().join("config.toml"), w.codex().join("AGENTS.md"), w.cursor().join("mcp.json"), w.gemini().join("settings.json")] {
            assert!(!absent.exists(), "explicit mode must not write {}", absent.display());
        }
        assert!(!m.claude_mcp_registered);
        assert_eq!(installed(&w.home), ["claude-code (skill: explicit)", "codex (prompt)", "cursor (skill: explicit)", "gemini-cli (command)"]);
    }

    #[test]
    fn auto_mode_writes_the_server_and_the_snippet() {
        let (w, mut m) = machine("auto");
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert_eq!(read(&w.claude_skill_dir().join("SKILL.md")), SKILL_MD);
        assert!(json_has_server(&w.claude_json()));
        assert!(toml_has_server(&w.codex().join("config.toml")));
        assert!(read(&w.codex().join("AGENTS.md")).contains("secrets_request"));
        assert!(json_has_server(&w.cursor().join("mcp.json")));
        assert!(json_has_server(&w.gemini().join("settings.json")));
        for absent in [w.codex_prompt(), w.gemini_command(), w.cursor_skill_dir()] {
            assert!(!absent.exists(), "auto mode must not write {}", absent.display());
        }
        assert_eq!(installed(&w.home), ["claude-code (skill: auto, mcp)", "codex (mcp, snippet)", "cursor (mcp)", "gemini-cli (mcp)"]);
    }

    /// The point of explicit mode: after the switch nothing automatic is left, and the
    /// user's other entries in the shared configs are exactly as they were.
    #[test]
    fn switching_to_explicit_removes_every_automatic_hook_and_keeps_the_users_entries() {
        let (w, mut m) = machine("to-explicit");
        fs::write(w.codex().join("config.toml"), "# mine\nmodel = \"o3\"\n\n[mcp_servers.github]\ncommand = \"gh-mcp\"\n").unwrap();
        fs::write(w.codex().join("AGENTS.md"), "# My rules\n\nBe brief.\n").unwrap();
        fs::write(w.cursor().join("mcp.json"), "{\"mcpServers\":{\"github\":{\"command\":\"gh-mcp\"}}}").unwrap();
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert!(read(&w.codex().join("AGENTS.md")).contains(SNIPPET_MARK));

        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        for (p, entry) in [(w.claude_json(), "tokenstash"), (w.cursor().join("mcp.json"), "tokenstash"), (w.gemini().join("settings.json"), "tokenstash")] {
            assert!(!json_has_server(&p), "{}", p.display());
            assert!(!read(&p).contains(entry), "{}: {}", p.display(), read(&p));
        }
        // Files init created that now hold nothing are gone; the user's Cursor file stays.
        assert!(!w.claude_json().exists() && !w.gemini().join("settings.json").exists());
        assert!(w.cursor().join("mcp.json").exists());
        let codex_toml = read(&w.codex().join("config.toml"));
        assert!(!toml_has_server(&w.codex().join("config.toml")));
        assert!(codex_toml.contains("# mine") && codex_toml.contains("model = \"o3\"") && codex_toml.contains("[mcp_servers.github]"), "{codex_toml}");
        assert_eq!(read(&w.codex().join("AGENTS.md")), "# My rules\n\nBe brief.\n");
        assert!(read(&w.cursor().join("mcp.json")).contains("gh-mcp"));
        assert!(read(&w.claude_skill_dir().join("SKILL.md")).contains("disable-model-invocation: true"));
        assert!(w.codex_prompt().is_file() && w.gemini_command().is_file() && w.cursor_skill_dir().join("SKILL.md").is_file());
        assert_eq!(installed(&w.home), ["claude-code (skill: explicit)", "codex (prompt)", "cursor (skill: explicit)", "gemini-cli (command)"]);
    }

    #[test]
    fn switching_back_to_auto_removes_the_commands_and_reinstalls_the_server() {
        let (w, mut m) = machine("to-auto");
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert!(!w.codex_prompt().exists() && !w.gemini_command().exists() && !w.cursor_skill_dir().exists());
        assert_eq!(read(&w.claude_skill_dir().join("SKILL.md")), SKILL_MD);
        assert!(json_has_server(&w.claude_json()) && toml_has_server(&w.codex().join("config.toml")));
        assert_eq!(installed(&w.home), ["claude-code (skill: auto, mcp)", "codex (mcp, snippet)", "cursor (mcp)", "gemini-cli (mcp)"]);
        // The released files are out of the manifest, so undo does not report them.
        assert!(!m.files.iter().any(|(p, _)| p == &w.codex_prompt() || p == &w.gemini_command()));
        assert!(!m.dirs.iter().any(|d| d == &w.cursor_skill_dir()));
    }

    /// Whatever the mode history, undo puts the machine back as init found it.
    #[test]
    fn undo_after_switching_restores_the_original_files() {
        let (w, mut m) = machine("undo");
        let codex_toml = "[mcp_servers.github]\ncommand = \"gh-mcp\"\n";
        fs::write(w.codex().join("config.toml"), codex_toml).unwrap();
        fs::create_dir_all(w.codex_prompt().parent().unwrap()).unwrap();
        fs::write(w.codex_prompt().parent().unwrap().join("other.md"), "keep").unwrap();
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        let root = m.root.clone();
        assert_eq!(undo_with(m).unwrap(), 0);
        assert!(!root.join("init.manifest.json").exists());
        assert_eq!(read(&w.codex().join("config.toml")), codex_toml);
        for gone in [w.claude_skill_dir(), w.cursor_skill_dir(), w.codex_prompt(), w.gemini_command(), w.claude_json(), w.codex().join("AGENTS.md"), w.cursor().join("mcp.json"), w.gemini().join("settings.json")] {
            assert!(!gone.exists(), "{} should be gone", gone.display());
        }
        assert_eq!(read(&w.codex_prompt().parent().unwrap().join("other.md")), "keep", "the shared prompts dir is not init's");
        assert!(installed(&w.home).is_empty());
    }

    #[test]
    fn a_pre_existing_command_file_is_restored_not_deleted() {
        let (w, mut m) = machine("preexisting");
        fs::create_dir_all(w.codex_prompt().parent().unwrap()).unwrap();
        fs::write(w.codex_prompt(), "my own prompt").unwrap();
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert!(read(&w.codex_prompt()).contains("/prompts:tokenstash"));
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert_eq!(read(&w.codex_prompt()), "my own prompt");
    }

    #[test]
    fn a_registration_init_did_not_make_is_still_removed_in_explicit_mode() {
        let (w, mut m) = machine("foreign");
        fs::write(w.cursor().join("mcp.json"), "{\"mcpServers\":{\"tokenstash\":{\"command\":\"/old/tokenstash\",\"args\":[\"mcp\"]},\"github\":{\"command\":\"gh-mcp\"}}}").unwrap();
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert!(!json_has_server(&w.cursor().join("mcp.json")));
        assert!(read(&w.cursor().join("mcp.json")).contains("gh-mcp"));
        // ...and undo puts the user's registration back, since init backed the file up first.
        assert_eq!(undo_with(m).unwrap(), 0);
        assert!(read(&w.cursor().join("mcp.json")).contains("/old/tokenstash"));
    }

    #[test]
    fn the_snippet_is_stripped_exactly_and_a_hand_edited_one_is_left_alone() {
        let d = scratch("snippet");
        let p = d.join("AGENTS.md");
        fs::write(&p, "# Rules\n").unwrap();
        append_snippet_for(&p, AgentMode::Auto).unwrap();
        append_snippet_for(&p, AgentMode::Auto).unwrap();
        assert_eq!(read(&p).matches(SNIPPET_MARK).count(), 1);
        strip_snippet(&p).unwrap();
        assert_eq!(read(&p), "# Rules\n");
        // Snippet first, user text after it.
        fs::write(&p, format!("{}\n# After\n", snippet_for(AgentMode::Auto))).unwrap();
        strip_snippet(&p).unwrap();
        assert_eq!(read(&p), "# After\n");
        // No closing mark: refuse.
        fs::write(&p, format!("{SNIPPET_MARK}\nedited by hand\n")).unwrap();
        assert!(strip_snippet(&p).is_err());
        assert!(read(&p).contains("edited by hand"));
    }

    #[test]
    fn the_explicit_snippet_never_tells_the_agent_to_run_tokenstash() {
        let s = snippet_for(AgentMode::Explicit);
        for rule in ["Never ask the user to paste a secret", "invent a stand-in value by any route", "never read, print or quote"] {
            assert!(s.contains(rule), "{rule}: {s}");
        }
        assert!(s.contains("do not run tokenstash unless they invoke it"));
        assert!(!s.contains("secrets_request") && !s.contains("tokenstash need"));
        assert!(s.starts_with(SNIPPET_MARK) && s.trim_end().ends_with(SNIPPET_END));
    }

    #[test]
    fn a_non_default_home_is_baked_into_auto_registrations_only() {
        let (mut w, mut m) = machine("ts-home");
        w.ts_home = Some("/srv/ts".into());
        wire(&mut m, &w, AgentMode::Auto).unwrap();
        assert!(read(&w.claude_json()).contains("\"TOKENSTASH_HOME\": \"/srv/ts\""));
        assert!(read(&w.codex().join("config.toml")).contains("TOKENSTASH_HOME = \"/srv/ts\""));
        wire(&mut m, &w, AgentMode::Explicit).unwrap();
        assert!(!read(&w.codex().join("config.toml")).contains("/srv/ts"));
    }
}
