use crate::cmd::need::status_icon;
use crate::util::{self, App};
use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use tokenstash_core::stash::stash_key;
use tokenstash_core::Config;

#[derive(Args)]
pub struct TasksArgs {
    /// Every project, not just this one.
    #[arg(long)]
    pub all: bool,
    /// Include answered/denied/expired.
    #[arg(long)]
    pub history: bool,
    #[arg(long)]
    pub json: bool,
}

pub fn tasks(a: TasksArgs) -> Result<i32> {
    let app = App::open()?;
    app.db.expire_overdue()?;
    let project = tokenstash_core::project::current();
    let pid = project.to_string_lossy().to_string();
    let list = app.db.list_tasks(if a.all { None } else { Some(&pid) }, !a.history)?;
    if a.json {
        println!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(0);
    }
    if list.is_empty() {
        println!("no {}tasks{}", if a.history { "" } else { "open " }, if a.all { "" } else { " in this project" });
        return Ok(0);
    }
    for t in &list {
        let what = match t.kind {
            tokenstash_core::db::TaskKind::Secret => t.name.clone().unwrap_or_default(),
            tokenstash_core::db::TaskKind::Approval => format!("approve {}", crate::util::approval_names(&t.names).join(", ")),
            tokenstash_core::db::TaskKind::Human => t.title.clone(),
        };
        println!("{} {:<10} {:<40} {:<24} {}", status_icon(&t.status), t.id, what, util::short(&t.project), t.agent);
    }
    // Printed to stdout, so the TTY check must be stdout's.
    let state = crate::notify::inbox_state(&app.cfg);
    println!("\ninbox: {}", util::inbox_url_tty(&app.cfg, None, state, util::Stream::Stdout));
    if let Some(why) = util::inbox_unavailable(&app.cfg, state) {
        println!("       {why}");
    }
    Ok(0)
}

#[derive(Args)]
pub struct ListArgs {
    #[arg(long)]
    pub json: bool,
}

pub fn list(a: ListArgs) -> Result<i32> {
    let app = App::open()?;
    let secrets = app.db.list_secrets()?;
    if a.json {
        println!("{}", serde_json::to_string_pretty(&secrets)?);
        return Ok(0);
    }
    if secrets.is_empty() {
        println!("no secrets indexed in {}. Run `tokenstash need SOME_KEY` from a project to start.", tokenstash_core::config::config_dir().display());
        println!("(the {} stash itself is per-user; a key stored under another TOKENSTASH_HOME is adopted here, and listed, the first time a project needs it)", app.stash.backend());
        return Ok(0);
    }
    println!("{:<36} {:<10} {:<18} {:<10} LAST USED", "NAME", "IDENTITY", "PROVIDER", "FLAGS");
    for s in &secrets {
        let mut flags = vec![];
        if s.sensitive { flags.push("sensitive"); }
        if s.stale { flags.push("STALE"); }
        println!("{:<36} {:<10} {:<18} {:<10} {}", s.name, s.identity, s.provider.clone().unwrap_or_default(), flags.join(","), s.last_used.clone().unwrap_or_default());
    }
    for s in secrets.iter().filter(|s| s.stale) {
        println!("  {}@{}: {}", s.name, s.identity, s.stale_reason.clone().unwrap_or_else(|| "stale".into()));
    }
    println!("\n{} secrets in the {} stash (values never shown)", secrets.len(), app.stash.backend());
    Ok(0)
}

#[derive(Args)]
pub struct ForgetArgs {
    pub name: String,
    #[arg(long, default_value = "default")]
    pub identity: String,
}

pub fn forget(a: ForgetArgs) -> Result<i32> {
    let app = App::open()?;
    let had = app.stash.delete(&stash_key(&a.name, &a.identity))?;
    let meta = app.db.delete_secret(&a.name, &a.identity)?;
    app.db.audit(None, None, "forget", Some(&a.name), Some(&a.identity), None)?;
    if had || meta {
        println!("✓ forgot {}@{}", a.name, a.identity);
    } else {
        println!("nothing stored for {}@{}", a.name, a.identity);
    }
    Ok(0)
}

#[derive(Args)]
pub struct BindArgs {
    pub name: String,
    #[arg(long)]
    pub identity: String,
    #[arg(long)]
    pub project: Option<PathBuf>,
}

pub fn bind(a: BindArgs) -> Result<i32> {
    let app = App::open()?;
    let project = util::project_from(&a.project);
    app.db.set_binding(&project.to_string_lossy(), &a.name, &a.identity)?;
    println!("✓ {} → {}@{} for {}", a.name, a.name, a.identity, tokenstash_core::project::short(&project));
    Ok(0)
}

#[derive(Args)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub cmd: Option<TrustCmd>,
}

#[derive(Subcommand)]
pub enum TrustCmd {
    /// Add a trust root (defaults to cwd).
    Add { path: Option<PathBuf> },
    /// Remove a trust root.
    Rm { path: PathBuf },
    /// List trust roots.
    List,
}

pub fn trust(a: TrustArgs) -> Result<i32> {
    let mut cfg = Config::load()?;
    match a.cmd.unwrap_or(TrustCmd::List) {
        TrustCmd::Add { path } => {
            let p = path.unwrap_or(std::env::current_dir()?);
            let p = p.canonicalize().unwrap_or(p);
            if !cfg.trust_roots.contains(&p) {
                cfg.trust_roots.push(p.clone());
                cfg.save()?;
            }
            println!("✓ trusted {}", tokenstash_core::project::short(&p));
        }
        TrustCmd::Rm { path } => {
            let p = path.canonicalize().unwrap_or(path);
            let before = cfg.trust_roots.len();
            cfg.trust_roots.retain(|r| r != &p);
            if cfg.trust_roots.len() == before {
                bail!("{} is not a trust root", p.display());
            }
            cfg.save()?;
            println!("✓ removed {}", tokenstash_core::project::short(&p));
        }
        TrustCmd::List => {
            if cfg.trust_roots.is_empty() {
                println!("no trust roots — every project will ask once. Run `tokenstash trust add ~/code`.");
            }
            for r in &cfg.trust_roots {
                println!("{}", tokenstash_core::project::short(r));
            }
        }
    }
    Ok(0)
}

#[derive(Args)]
pub struct AuditArgs {
    #[arg(long, default_value = "30")]
    pub limit: usize,
}

pub fn audit(a: AuditArgs) -> Result<i32> {
    let app = App::open()?;
    for (ts, project, agent, action, name, identity, detail) in app.db.recent_audit(a.limit)? {
        println!(
            "{ts}  {:<14} {:<30} {:<24} {:<12} {}",
            action,
            name.map(|n| match identity { Some(i) if i != "default" => format!("{n}@{i}"), _ => n }).unwrap_or_default(),
            project.map(|p| util::short(&p)).unwrap_or_default(),
            agent.unwrap_or_default(),
            detail.unwrap_or_default()
        );
    }
    Ok(0)
}

// ---------- rotation ----------

#[derive(Args)]
pub struct RotateArgs {
    pub name: String,
    #[arg(long, default_value = "default")]
    pub identity: String,
    #[arg(long)]
    pub project: Option<PathBuf>,
}

/// Mark a key for replacement and file the paste card now. The old value stays in the
/// stash until the new one lands; every project still holding it is rewritten then.
pub fn rotate(a: RotateArgs) -> Result<i32> {
    let app = App::open()?;
    let project = util::project_from(&a.project);
    let agent = tokenstash_core::project::detect_agent();
    let t = tokenstash_core::tasks::rotate(&app.ctx(), &project, &agent, &a.name, &a.identity)?;
    let state = crate::notify::ensure_inbox(&app.cfg);
    crate::notify::desktop(&app.cfg, &format!("Replace {}", a.name), "you asked to rotate it", &util::inbox_notice(&app.cfg, Some(&t.id), state));
    println!("⏳ {}@{} marked for rotation — task {} → {}", a.name, a.identity, t.id, util::inbox_url_tty(&app.cfg, Some(&t.id), state, util::Stream::Stdout));
    println!("  paste the NEW key first; revoke the old one in the dashboard after it says stored");
    Ok(tokenstash_core::exit::PENDING)
}

#[derive(Args)]
pub struct ReportBadArgs {
    pub name: String,
    #[arg(long, default_value = "default")]
    pub identity: String,
    /// HTTP status the provider returned (401, 403, ...).
    #[arg(long)]
    pub status: Option<u16>,
    /// The provider's error text, without the key.
    #[arg(long)]
    pub message: Option<String>,
    #[arg(long)]
    pub project: Option<PathBuf>,
}

/// Agent-facing. Always prints the same line whatever happened: the agent learns the
/// outcome from its next `need` (card vs inject), never from here — otherwise this is a
/// stash-existence oracle for a hostile repo.
pub fn report_bad(a: ReportBadArgs) -> Result<i32> {
    let app = App::open()?;
    let project = util::project_from(&a.project);
    let agent = tokenstash_core::project::detect_agent();
    let _ = tokenstash_core::tasks::report_bad(&app.ctx(), &project, &agent, &a.name, &a.identity, a.status, a.message.as_deref())?;
    println!("ok — run `tokenstash need {}` again; if the key is dead the user will be asked for a replacement", a.name);
    Ok(0)
}

#[derive(Args)]
pub struct CheckArgs {
    /// Only these names (default: every key with a registry liveness check).
    pub names: Vec<String>,
    /// Only re-test keys currently marked stale (and un-mark them if the provider accepts).
    #[arg(long)]
    pub stale_only: bool,
    #[arg(long)]
    pub json: bool,
}

/// Sweep the stash through the registry's liveness probes. Human-only: it sends every key
/// to its provider and prints an inventory, so it refuses to run for an agent or a pipe.
pub fn check(a: CheckArgs) -> Result<i32> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() || tokenstash_core::project::detect_agent() != "unknown" {
        bail!("`tokenstash check` is for a person at a terminal: it sends each key to its provider and lists what you have. Run it yourself.");
    }
    let app = App::open()?;
    let mut rows = vec![];
    for m in app.db.list_secrets()? {
        if !a.names.is_empty() && !a.names.contains(&m.name) { continue; }
        if a.stale_only && !m.stale { continue; }
        let Some(check) = tokenstash_core::registry::lookup(&m.name).and_then(|p| p.check.clone()) else {
            rows.push((m.name.clone(), m.identity.clone(), "no check".to_string(), m.stale));
            continue;
        };
        let Some(v) = app.stash.get(&stash_key(&m.name, &m.identity))? else {
            rows.push((m.name.clone(), m.identity.clone(), "not in stash".to_string(), m.stale));
            continue;
        };
        let verdict = tokenstash_core::validate::liveness(&check, &v);
        let status = match verdict {
            tokenstash_core::validate::Liveness::Ok => { app.db.set_verified(&m.name, &m.identity)?; "ok".to_string() }
            tokenstash_core::validate::Liveness::Rejected(code) => {
                let reason = format!("rejected by the provider (HTTP {code}) on {} during `tokenstash check`", tokenstash_core::now());
                app.db.mark_stale(&m.name, &m.identity, true, Some(&reason))?;
                app.db.audit(None, None, "check.rejected", Some(&m.name), Some(&m.identity), Some(&format!("HTTP {code}")))?;
                format!("REJECTED (HTTP {code}) → stale")
            }
            tokenstash_core::validate::Liveness::Unknown(e) => format!("unknown ({})", e.chars().take(40).collect::<String>()),
        };
        let stale_now = app.db.get_secret(&m.name, &m.identity)?.map(|x| x.stale).unwrap_or(false);
        rows.push((m.name.clone(), m.identity.clone(), status, stale_now));
        std::thread::sleep(std::time::Duration::from_millis(200)); // polite pacing
    }
    if a.json {
        println!("{}", serde_json::to_string_pretty(&rows.iter().map(|(n, i, st, stale)| serde_json::json!({ "name": n, "identity": i, "result": st, "stale": stale })).collect::<Vec<_>>())?);
        return Ok(0);
    }
    if rows.is_empty() { println!("nothing to check"); return Ok(0); }
    println!("{:<36} {:<10} RESULT", "NAME", "IDENTITY");
    for (n, i, st, _) in &rows { println!("{n:<36} {i:<10} {st}"); }
    let stale = rows.iter().filter(|r| r.3).count();
    if stale > 0 { println!("\n{stale} stale — the next `tokenstash need` for each asks for a replacement (or run `tokenstash rotate NAME`)"); }
    Ok(0)
}
