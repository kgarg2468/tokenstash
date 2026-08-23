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
}

pub fn init(a: InitArgs) -> Result<i32> {
    let mut cfg = Config::load()?;
    let fresh = !Config::exists();

    // 1. stash backend: probe and pin it so later calls don't re-probe
    let stash = tokenstash_core::stash::open(&cfg)?;
    let backend = stash.backend();
    if cfg.stash_backend.is_none() && backend != "insecure-file" {
        cfg.stash_backend = Some(match backend { "secret-service" | "os-keychain" => "keyring".into(), b => b.into() });
    }
    println!("✓ stash backend: {backend}{}", if backend == "keyutils" { "  (Linux kernel keyring: survives logout, not reboot; install a Secret Service like gnome-keyring for persistence)" } else { "" });

    // 2. trust roots
    if cfg.trust_roots.is_empty() {
        cfg.trust_roots = Config::default_trust_roots();
    }
    for t in &a.trust {
        let t = t.canonicalize().unwrap_or(t.clone());
        if !cfg.trust_roots.contains(&t) {
            cfg.trust_roots.push(t);
        }
    }
    cfg.save()?;
    tokenstash_core::Db::open_default()?;
    println!("✓ trust roots: {}", cfg.trust_roots.iter().map(|p| tokenstash_core::project::short(p)).collect::<Vec<_>>().join(", "));
    println!("  (projects here get silent injection; elsewhere you're asked once per project — `tokenstash trust add <dir>`)");

    // 3. agents
    if !a.no_agents {
        let exe = std::env::current_exe()?;
        let exe_s = exe.display().to_string();
        let home = dirs::home_dir().unwrap_or_default();

        // Claude Code
        if home.join(".claude").is_dir() || which("claude") {
            let skill_dir = home.join(".claude/skills/tokenstash");
            fs::create_dir_all(&skill_dir)?;
            fs::write(skill_dir.join("SKILL.md"), SKILL_MD)?;
            let added = if which("claude") {
                std::process::Command::new("claude")
                    .args(["mcp", "add", "-s", "user", "tokenstash", "--", &exe_s, "mcp"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            } else {
                false
            };
            let mcp_note = if added { ", MCP server registered".to_string() } else { format!("; register MCP with: claude mcp add -s user tokenstash -- {exe_s} mcp") };
            println!("✓ Claude Code: skill installed{mcp_note}");
        }

        // Codex
        let codex = home.join(".codex");
        if codex.is_dir() {
            let cfg_path = codex.join("config.toml");
            let mut s = fs::read_to_string(&cfg_path).unwrap_or_default();
            if !s.contains("[mcp_servers.tokenstash]") {
                if !s.is_empty() && !s.ends_with('\n') { s.push('\n'); }
                // toml::Value renders a correctly escaped string (backslashes, quotes, unicode)
                let cmd = toml::Value::String(exe_s.clone()).to_string();
                s.push_str(&format!("\n[mcp_servers.tokenstash]\ncommand = {cmd}\nargs = [\"mcp\"]\n"));
                fs::write(&cfg_path, s)?;
            }
            append_snippet(&codex.join("AGENTS.md"))?;
            println!("✓ Codex: MCP server + AGENTS.md");
        }

        // Cursor
        let cursor = home.join(".cursor");
        if cursor.is_dir() {
            match merge_mcp_json(&cursor.join("mcp.json"), &exe_s) {
                Ok(()) => println!("✓ Cursor: MCP server registered (~/.cursor/mcp.json)"),
                Err(e) => println!("! Cursor: left ~/.cursor/mcp.json untouched — {e}"),
            }
        }

        // Gemini CLI
        let gemini = home.join(".gemini");
        if gemini.is_dir() {
            match merge_mcp_json(&gemini.join("settings.json"), &exe_s) {
                Ok(()) => println!("✓ Gemini CLI: MCP server registered"),
                Err(e) => println!("! Gemini CLI: left ~/.gemini/settings.json untouched — {e}"),
            }
        }
    }

    if a.project {
        let p = std::env::current_dir()?.join("AGENTS.md");
        append_snippet(&p)?;
        println!("✓ wrote tokenstash section to {}", p.display());
    }

    if fresh {
        println!("\nNext: from any project, run   tokenstash need OPENAI_API_KEY");
    }
    Ok(0)
}

/// Add `mcpServers.tokenstash` to a JSON config owned by another tool. If the file exists
/// but cannot be parsed as a JSON object, refuse rather than replace it.
fn merge_mcp_json(p: &Path, exe: &str) -> Result<()> {
    let mut v: serde_json::Value = match fs::read_to_string(p) {
        Ok(s) if s.trim().is_empty() => serde_json::json!({}),
        Ok(s) => serde_json::from_str(&s).map_err(|e| anyhow::anyhow!("{} is not valid JSON ({e}); fix it or add the MCP server by hand", p.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(e) => return Err(e.into()),
    };
    let root = v.as_object_mut().ok_or_else(|| anyhow::anyhow!("{} root is not a JSON object", p.display()))?;
    let servers = root.entry("mcpServers").or_insert(serde_json::json!({}));
    let m = servers.as_object_mut().ok_or_else(|| anyhow::anyhow!("{} has a non-object mcpServers", p.display()))?;
    m.insert("tokenstash".into(), serde_json::json!({ "command": exe, "args": ["mcp"] }));
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
