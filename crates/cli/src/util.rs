use anyhow::Result;
use std::path::PathBuf;
use tokenstash_core::stash::Stash;
use tokenstash_core::tasks::Ctx;
use tokenstash_core::{Config, Db};

pub struct App {
    pub cfg: Config,
    pub db: Db,
    pub stash: Box<dyn Stash>,
}

impl App {
    pub fn open() -> Result<Self> {
        let cfg = Config::load()?;
        let db = Db::open_default()?;
        let stash = tokenstash_core::stash::open(&cfg)?;
        Ok(Self { cfg, db, stash })
    }
    pub fn ctx(&self) -> Ctx<'_> {
        Ctx { cfg: &self.cfg, db: &self.db, stash: self.stash.as_ref() }
    }
}

pub fn project_from(arg: &Option<PathBuf>) -> PathBuf {
    match arg {
        Some(p) => tokenstash_core::project::canonical(p),
        None => tokenstash_core::project::current(),
    }
}

pub fn agent_from(arg: &Option<String>) -> String {
    arg.clone().unwrap_or_else(tokenstash_core::project::detect_agent)
}

/// Agent-safe inbox URL — no auth token. This lands in CLI stdout, `--json`, and MCP
/// results, all of which end up in agent transcripts. Never put the token here.
pub fn inbox_url(cfg: &Config, task_id: Option<&str>) -> String {
    match task_id {
        Some(id) => format!("http://127.0.0.1:{}/t/{}", cfg.inbox_port, id),
        None => format!("http://127.0.0.1:{}/", cfg.inbox_port),
    }
}

/// Human-only deep link carrying the inbox session token (for desktop notifications,
/// which the agent never sees).
pub fn inbox_link(cfg: &Config, task_id: Option<&str>) -> String {
    format!("{}?t={}", inbox_url(cfg, task_id), crate::notify::inbox_token())
}

pub fn short(p: &str) -> String {
    tokenstash_core::project::short(std::path::Path::new(p))
}
