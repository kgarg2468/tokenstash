use crate::notify;
use anyhow::Result;
use tokenstash_core::{Config, Db};

pub fn doctor() -> Result<i32> {
    let mut ok = true;
    let check = |label: &str, good: bool, detail: String| {
        println!("{} {:<28} {}", if good { "✓" } else { "✗" }, label, detail);
        good
    };

    let cfg_exists = Config::exists();
    ok &= check("config", cfg_exists, tokenstash_core::config::config_path().display().to_string() + if cfg_exists { "" } else { "  (run `tokenstash init`)" });
    let cfg = Config::load()?;

    match tokenstash_core::stash::open(&cfg) {
        Ok(s) => {
            let probe = match s.backend() {
                "insecure-file" => Ok(()),
                _ => tokenstash_core::stash::KeyringStash::auto().and_then(|k| k.probe()),
            };
            ok &= check("stash backend", probe.is_ok(), format!("{}{}", s.backend(), probe.err().map(|e| format!("  ({e})")).unwrap_or_default()));
        }
        Err(e) => { ok &= check("stash backend", false, e.to_string()); }
    }

    match Db::open_default() {
        Ok(db) => {
            let n = db.list_secrets().map(|v| v.len()).unwrap_or(0);
            let open = db.list_tasks(None, true).map(|v| v.len()).unwrap_or(0);
            check("database", true, format!("{} secrets indexed, {} open tasks", n, open));
        }
        Err(e) => { ok &= check("database", false, e.to_string()); }
    }

    check("registry", true, format!("{} providers", tokenstash_core::registry::count()));
    ok &= check("trust roots", !cfg.trust_roots.is_empty(), if cfg.trust_roots.is_empty() { "none (every project will ask once)".into() } else { cfg.trust_roots.iter().map(|p| tokenstash_core::project::short(p)).collect::<Vec<_>>().join(", ") });
    check("inbox", true, format!("{}  {}", crate::util::inbox_url_tty(&cfg, None), notify::inbox_status(&cfg)));

    let home = dirs::home_dir().unwrap_or_default();
    let claude_skill = home.join(".claude/skills/tokenstash/SKILL.md").exists();
    let codex = std::fs::read_to_string(home.join(".codex/config.toml")).map(|s| s.contains("mcp_servers.tokenstash")).unwrap_or(false);
    let cursor = std::fs::read_to_string(home.join(".cursor/mcp.json")).map(|s| s.contains("tokenstash")).unwrap_or(false);
    let mut agents = vec![];
    if claude_skill { agents.push("claude-code"); }
    if codex { agents.push("codex"); }
    if cursor { agents.push("cursor"); }
    check("agents", true, if agents.is_empty() { "none configured (run `tokenstash init`)".into() } else { agents.join(", ") });

    let project = tokenstash_core::project::current();
    let inside = tokenstash_core::trust::inside_roots(&project, &cfg);
    check("this project", true, format!("{}  {}", tokenstash_core::project::short(&project), if inside { "trusted" } else { "outside trust roots → will ask once" }));
    check("binary", true, std::env::current_exe()?.display().to_string());

    Ok(if ok { 0 } else { 1 })
}
