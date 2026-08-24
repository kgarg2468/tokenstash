use crate::notify::Inbox;
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

/// Which stream a URL is about to be written to. A TTY check is only meaningful for the
/// stream that is actually being written: `run` prints its inbox line to stderr while `tasks`
/// and `doctor` print to stdout, and a pipeline routinely redirects one and not the other.
/// Testing stdout and then printing to stderr would put the token into a captured stderr
/// whenever stdout merely happened to be a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

fn is_terminal(stream: Stream) -> bool {
    use std::io::IsTerminal;
    match stream {
        Stream::Stdout => std::io::stdout().is_terminal(),
        Stream::Stderr => std::io::stderr().is_terminal(),
    }
}

/// The inbox URL carrying `?t=<session token>`, which authenticates the first click and is
/// then swapped for a cookie. For surfaces a person reads directly: the desktop notification
/// and `tokenstash open`.
///
/// `state` is a required argument on purpose. The token is appended only when ownership of
/// the port has been *proved* ([`Inbox::Ours`]). Handing `?t=` to a listener that failed the
/// `/verify` challenge would give a squatter exactly the credential it needs to impersonate
/// the inbox and collect whatever the human pastes next — the URL is the one place the token
/// leaves this process, so the check belongs here, where no new call site can forget it.
/// Falls back to the bare URL otherwise; callers talking to a human should use
/// [`inbox_notice`], which explains itself instead of handing over a dead or hostile link.
pub fn inbox_url_human(cfg: &Config, task_id: Option<&str>, state: Inbox) -> String {
    let url = inbox_url(cfg, task_id);
    match (state, crate::inbox_auth::ensure_token()) {
        (Inbox::Ours, Ok(t)) => format!("{url}?t={t}"),
        _ => url,
    }
}

/// Tokened only when we are demonstrably talking to a person at *this stream's* terminal and
/// the inbox has proved it is ours. `tasks`, `doctor` and `run` print for a human but are also
/// run by agents that capture the output; when the stream is not a TTY (a pipe, a file, an
/// agent's capture buffer) they get the bare URL. An agent that allocates a PTY can still see
/// the token here — that is the known limit of a TTY heuristic, and the reason no
/// unconditional surface ever prints it.
///
/// Only a *proved* inbox gets a link at all, bare or tokened, on any stream: a loopback URL
/// in front of a person is an invitation to paste a key into whatever answers there, and an
/// agent relays the line verbatim. `Down` gets no link either — a squatter can bind the port
/// between our probe and the click.
pub fn inbox_url_tty(cfg: &Config, task_id: Option<&str>, state: Inbox, stream: Stream) -> String {
    if !matches!(state, Inbox::Ours) {
        return inbox_notice(cfg, task_id, state);
    }
    if is_terminal(stream) {
        inbox_url_human(cfg, task_id, state)
    } else {
        inbox_url(cfg, task_id)
    }
}

/// Agent-facing: the bare URL (never the token) when the inbox is proved ours; otherwise the
/// notice and no link, because the agent relays this line to a person.
pub fn inbox_url_agent(cfg: &Config, task_id: Option<&str>, state: Inbox) -> String {
    if !matches!(state, Inbox::Ours) {
        inbox_notice(cfg, task_id, state)
    } else {
        inbox_url(cfg, task_id)
    }
}

/// Why we are not sending you to the inbox, when we are not. `None` means go ahead.
pub fn inbox_unavailable(cfg: &Config, state: Inbox) -> Option<String> {
    match state {
        Inbox::Ours => None,
        Inbox::Foreign => Some(format!(
            "port {} is held by another process; not sending you there. Free the port or change inbox_port in {}.",
            cfg.inbox_port,
            tokenstash_core::config::config_path().display()
        )),
        Inbox::Down => Some("the inbox is not running; start it with `tokenstash open`.".to_string()),
    }
}

/// The one line we put in front of a person telling them where to go: the tokened URL when
/// ownership is proved, and why we are not sending them anywhere when it is not. Never a link
/// to a listener that failed the proof — even a bare one would walk the human into an
/// impostor's paste form.
pub fn inbox_notice(cfg: &Config, task_id: Option<&str>, state: Inbox) -> String {
    match inbox_unavailable(cfg, state) {
        None => inbox_url_human(cfg, task_id, state),
        Some(why) => format!("tokenstash: {why}"),
    }
}

pub fn short(p: &str) -> String {
    tokenstash_core::project::short(std::path::Path::new(p))
}

/// Human display for approval entries: drop the "*" marker and the "@default" suffix.
pub fn approval_names(names: &[String]) -> Vec<String> {
    names.iter().filter(|n| n.as_str() != "*").map(|n| n.strip_suffix("@default").unwrap_or(n).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_home<T>(name: &str, f: impl FnOnce(Config) -> T) -> T {
        let _g = crate::inbox_auth::env_lock();
        let home = std::env::temp_dir().join(format!("tokenstash-util-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("TOKENSTASH_HOME", &home);
        let out = f(Config::default());
        std::env::remove_var("TOKENSTASH_HOME");
        let _ = std::fs::remove_dir_all(&home);
        out
    }

    #[test]
    fn the_token_is_only_attached_to_a_verified_inbox() {
        with_home("verified", |cfg| {
            let token = crate::inbox_auth::ensure_token().unwrap();
            // Proved ours: the human's link carries the token.
            let ours = inbox_url_human(&cfg, Some("t_abc"), Inbox::Ours);
            assert!(ours.contains(&format!("?t={token}")), "{ours}");
            assert!(ours.contains("/t/t_abc"));

            // Anything we could not prove is ours gets no token — a squatter on the port must
            // not be handed the credential that lets it impersonate the inbox.
            for state in [Inbox::Foreign, Inbox::Down] {
                let url = inbox_url_human(&cfg, None, state);
                assert!(!url.contains("t="), "{state:?} produced a tokened URL: {url}");
                assert!(!url.contains(&token), "{state:?} leaked the token: {url}");
            }
            // ...and the bare form never carries it, whatever the state.
            assert!(!inbox_url(&cfg, None).contains("t="));
        });
    }

    #[test]
    fn an_unverified_inbox_yields_an_explanation_not_a_link() {
        with_home("notice", |cfg| {
            let token = crate::inbox_auth::ensure_token().unwrap();
            assert_eq!(inbox_unavailable(&cfg, Inbox::Ours), None);

            let foreign = inbox_notice(&cfg, Some("t_abc"), Inbox::Foreign);
            assert!(foreign.contains("held by another process"), "{foreign}");
            assert!(!foreign.contains("http"), "a link to an unverified listener: {foreign}");
            assert!(!foreign.contains(&token));

            let down = inbox_notice(&cfg, None, Inbox::Down);
            assert!(down.contains("tokenstash open"), "{down}");
            assert!(!down.contains(&token));

            // Verified: the notice IS the tokened link.
            assert_eq!(inbox_notice(&cfg, None, Inbox::Ours), inbox_url_human(&cfg, None, Inbox::Ours));
        });
    }

    #[test]
    fn an_unproved_inbox_gets_no_link_on_any_surface() {
        with_home("unproved", |cfg| {
            for state in [Inbox::Foreign, Inbox::Down] {
                for stream in [Stream::Stdout, Stream::Stderr] {
                    let out = inbox_url_tty(&cfg, Some("t_abc"), state, stream);
                    assert!(!out.contains("http"), "{state:?}/{stream:?} linked to an unproved inbox: {out}");
                }
                let out = inbox_url_agent(&cfg, Some("t_abc"), state);
                assert!(!out.contains("http"), "agent surface linked to an unproved inbox: {out}");
            }
            assert!(inbox_url_agent(&cfg, None, Inbox::Ours).starts_with("http://127.0.0.1:"));
        });
    }

    #[test]
    fn a_non_terminal_stream_never_gets_the_token() {
        with_home("stream", |cfg| {
            let token = crate::inbox_auth::ensure_token().unwrap();
            // Under `cargo test` both streams are captured, so neither is a terminal: the
            // point is that each variant consults its own stream rather than a fixed one.
            for stream in [Stream::Stdout, Stream::Stderr] {
                if !is_terminal(stream) {
                    let url = inbox_url_tty(&cfg, None, Inbox::Ours, stream);
                    assert_eq!(url, inbox_url(&cfg, None), "{stream:?} tokened a captured stream");
                    assert!(!url.contains(&token));
                }
            }
        });
    }
}
