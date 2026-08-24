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

/// The inbox URL with NO session token. Every place an inbox link is built goes through here
/// or through [`inbox_url_human`] — there is no third spelling.
///
/// This is the agent-facing form. MCP tool results, `need --json`, `need`/`ask` stdout: all of
/// it is read by the model, so none of it may carry the token. The model already sees the
/// project's env file, so the token would not reveal a secret — but it would let the model
/// *answer* tasks, and answering is the human's yes: "store this value under this key name",
/// "trust this project with sensitive keys". An agent that could answer could inject a value
/// of its own choosing and self-approve the gate that exists to ask a person. See
/// `crate::inbox_auth`. A bare URL is still useful to the agent: it is what it tells the human
/// to open, and the human's own click (from the notification or `tokenstash open`) carries the
/// token.
pub fn inbox_url(cfg: &Config, task_id: Option<&str>) -> String {
    match task_id {
        Some(id) => format!("http://127.0.0.1:{}/t/{}", cfg.inbox_port, id),
        None => format!("http://127.0.0.1:{}/", cfg.inbox_port),
    }
}

/// The inbox URL carrying `?t=<session token>`, which authenticates the first click and is
/// then swapped for a cookie. ONLY for surfaces a person reads directly: the desktop
/// notification and `tokenstash open`. Falls back to the bare URL if the token cannot be
/// read — a link that 404s beats no link at all.
pub fn inbox_url_human(cfg: &Config, task_id: Option<&str>) -> String {
    let url = inbox_url(cfg, task_id);
    match crate::inbox_auth::ensure_token() {
        Ok(t) => format!("{url}?t={t}"),
        Err(_) => url,
    }
}

/// Tokened only when we are demonstrably talking to a person at a terminal. `tasks`, `doctor`
/// and `run` print to a terminal for a human but are also run by agents that capture the
/// output; when stdout is not a TTY (a pipe, a file, an agent's capture buffer) they get the
/// bare URL. An agent that allocates a PTY can still see the token here — that is the known
/// limit of a TTY heuristic, and the reason no unconditional surface ever prints it.
pub fn inbox_url_tty(cfg: &Config, task_id: Option<&str>) -> String {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        inbox_url_human(cfg, task_id)
    } else {
        inbox_url(cfg, task_id)
    }
}

pub fn short(p: &str) -> String {
    tokenstash_core::project::short(std::path::Path::new(p))
}

/// Human display for approval entries: drop the "*" marker and the "@default" suffix.
pub fn approval_names(names: &[String]) -> Vec<String> {
    names.iter().filter(|n| n.as_str() != "*").map(|n| n.strip_suffix("@default").unwrap_or(n).to_string()).collect()
}
