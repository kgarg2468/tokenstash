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
            tokenstash_core::db::TaskKind::Approval => format!("approve {}", t.names.iter().filter(|n| n.as_str() != "*").cloned().collect::<Vec<_>>().join(", ")),
            tokenstash_core::db::TaskKind::Human => t.title.clone(),
        };
        println!("{} {:<10} {:<40} {:<24} {}", status_icon(&t.status), t.id, what, util::short(&t.project), t.agent);
    }
    println!("\ninbox: {}", util::inbox_url(&app.cfg, None));
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
        println!("stash is empty. Run `tokenstash need SOME_KEY` from a project to start.");
        return Ok(0);
    }
    println!("{:<36} {:<10} {:<18} {:<10} {}", "NAME", "IDENTITY", "PROVIDER", "FLAGS", "LAST USED");
    for s in &secrets {
        let mut flags = vec![];
        if s.sensitive { flags.push("sensitive"); }
        if s.stale { flags.push("stale"); }
        println!("{:<36} {:<10} {:<18} {:<10} {}", s.name, s.identity, s.provider.clone().unwrap_or_default(), flags.join(","), s.last_used.clone().unwrap_or_default());
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
