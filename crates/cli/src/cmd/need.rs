use crate::notify;
use crate::util::{self, App};
use anyhow::Result;
use clap::Args;
use std::time::Duration;
use tokenstash_core::exit;
use tokenstash_core::need::{self, NeedOpts, Outcome};
use tokenstash_core::tasks::{self, HumanRequest, SecretRequest};

#[derive(Args)]
pub struct NeedArgs {
    /// Env var names, e.g. OPENAI_API_KEY RESEND_API_KEY
    #[arg(required = true)]
    pub names: Vec<String>,
    /// Why the agent needs it (shown to the human).
    #[arg(long)]
    pub why: Option<String>,
    /// Where to get it (overrides the registry).
    #[arg(long)]
    pub url: Option<String>,
    /// Step-by-step instructions (repeatable).
    #[arg(long = "step")]
    pub steps: Vec<String>,
    /// Regex the value must match.
    #[arg(long)]
    pub pattern: Option<String>,
    /// Identity label (work/personal). Defaults to the project binding or "default".
    #[arg(long)]
    pub identity: Option<String>,
    /// Wait for the human instead of returning immediately.
    #[arg(long)]
    pub blocking: bool,
    /// Seconds to wait when --blocking.
    #[arg(long, default_value = "600", requires = "blocking")]
    pub timeout: u64,
    /// Agent name for the audit log (auto-detected).
    #[arg(long)]
    pub agent: Option<String>,
    /// Ask again even if the user recently declined this key for this project.
    #[arg(long)]
    pub force: bool,
    /// Machine-readable output.
    #[arg(long)]
    pub json: bool,
}

pub fn need(a: NeedArgs) -> Result<i32> {
    // "Denied" is remembered for a day so a program failing in a loop cannot nag. Asking
    // again over that is the person's call, never the agent's.
    if a.force {
        util::require_human("need --force", "it asks again after the user said no")?;
    }
    let app = App::open()?;
    // The directory this command runs in is the project: a caller-named path would let a
    // script choose which directory's grants it uses. (Read-only `tasks`/`audit` keep --project.)
    let project = util::project_from(&None);
    let agent = util::agent_from(&a.agent);
    let opts = NeedOpts {
        req: SecretRequest { why: a.why.clone(), url: a.url.clone(), steps: a.steps.clone(), pattern: a.pattern.clone() },
        identity: a.identity.clone(),
        blocking: false,
        timeout: Duration::from_secs(a.timeout),
        force: a.force,
        require_approval: false,
    };
    let mut outcomes = need::need(&app.ctx(), &project, &agent, &a.names, &opts)?;

    if outcomes.iter().any(|o| o.is_pending()) {
        notify_pending(&app, &project, &agent, &outcomes);
        if a.blocking {
            // wait on the tasks already filed; never file a second set
            need::wait(&app.ctx(), &project, &mut outcomes, opts.timeout)?;
        }
    }

    // Only probed when something is pending: a hit never needs the inbox.
    let state = if outcomes.iter().any(|o| o.is_pending()) { notify::inbox_state(&app.cfg) } else { notify::Inbox::Down };
    if a.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "project": project,
            "env_file": app.cfg.env_file,
            "inbox": util::inbox_url_agent(&app.cfg, None, state),
            "results": outcomes,
        }))?);
    } else {
        for o in &outcomes {
            match o {
                Outcome::Injected { name, written_to, generated, unverified, .. } => {
                    let p = std::path::Path::new(written_to);
                    let rel = p.strip_prefix(&project).map(|r| r.display().to_string()).unwrap_or(written_to.clone());
                    println!("✓ {name} {} → {rel}", if *generated { "generated and injected" } else { "injected" });
                    if *unverified {
                        eprintln!("  {name}: delivered without re-checking it (provider unreachable or rate-limited, or checked moments ago by another process)");
                    }
                }
                Outcome::Pending { name, task_id, .. } => {
                    println!("⏳ {name} pending — task {task_id} → {}", util::inbox_url_agent(&app.cfg, Some(task_id), state));
                }
                Outcome::Denied { name, .. } => println!("✗ {name} denied by the user — do not ask again, and do not supply a stand-in value by any route; make the feature optional or report it blocked"),
                Outcome::Expired { name, .. } => println!("✗ {name} expired unanswered"),
            }
        }
        if outcomes.iter().any(|o| o.is_pending()) {
            // Only claim there is a link when there is one; with the inbox down or squatted
            // the line above is an explanation, and an agent following "open the link above"
            // would hand the user an error string as a URL.
            if matches!(state, notify::Inbox::Ours) {
                eprintln!("\nTell the user to open the link above: it works as-is for pasting a missing key. If the card is an approval (a stored key waiting for this directory's yes), the user approves it from the desktop notification or by running `tokenstash open` in a terminal. Continue with other work; `tokenstash tasks` shows the status.");
            } else {
                eprintln!("\nThere is no inbox link yet (see the message above). Tell the user to run `tokenstash open` in a terminal; that starts the inbox and opens it. Continue with other work; re-run this command or `tokenstash tasks` to check.");
            }
        }
    }
    Ok(code_for(&outcomes))
}

pub fn notify_pending(app: &App, project: &std::path::Path, agent: &str, outcomes: &[Outcome]) {
    let state = notify::ensure_inbox(&app.cfg);
    // One notification per card. A polling agent re-runs `need` every few seconds and gets
    // the same card back; the human must not get the same toast back.
    let fresh: Vec<&Outcome> = outcomes.iter().filter(|o| matches!(o, Outcome::Pending { task_id, .. } if app.db.mark_notified(task_id).unwrap_or(true))).collect();
    if fresh.is_empty() {
        return;
    }
    let pending: Vec<&str> = fresh.iter().map(|o| o.name()).collect();
    let first_id = fresh.iter().find_map(|o| match o { Outcome::Pending { task_id, .. } => Some(task_id.clone()), _ => None });
    notify::desktop(
        &app.cfg,
        &format!("{} needs {}", tokenstash_core::project::short(project), pending.join(", ")),
        &format!("requested by {agent}"),
        // The notification is read by the human and nothing else, so it is tokened — but only
        // if `state` says we proved the port is ours. Otherwise it explains itself instead of
        // walking the human, and the token, into whatever is squatting there.
        &util::inbox_notice(&app.cfg, first_id.as_deref(), state),
    );
}

pub fn code_for(outcomes: &[Outcome]) -> i32 {
    if outcomes.iter().any(|o| o.is_pending()) {
        exit::PENDING
    } else if outcomes.iter().any(|o| matches!(o, Outcome::Denied { .. })) {
        exit::DENIED
    } else if outcomes.iter().any(|o| matches!(o, Outcome::Expired { .. })) {
        exit::EXPIRED
    } else {
        exit::INJECTED
    }
}

#[derive(Args)]
pub struct AskArgs {
    /// What you need the human to do.
    pub title: String,
    #[arg(long)]
    pub why: Option<String>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long = "step")]
    pub steps: Vec<String>,
    /// confirm | text. A `text` answer is returned to the agent — tell the human not to paste secrets into it.
    #[arg(long, default_value = "confirm")]
    pub expects: String,
    #[arg(long)]
    pub blocking: bool,
    /// Seconds to wait when --blocking.
    #[arg(long, default_value = "600", requires = "blocking")]
    pub timeout: u64,
    #[arg(long)]
    pub agent: Option<String>,
    #[arg(long)]
    pub json: bool,
}

pub fn ask(a: AskArgs) -> Result<i32> {
    let app = App::open()?;
    let project = util::project_from(&None);
    let agent = util::agent_from(&a.agent);
    let t = tasks::create_human_task(
        &app.ctx(),
        &project,
        &agent,
        HumanRequest { title: a.title.clone(), why: a.why.clone(), url: a.url.clone(), steps: a.steps.clone(), expects: a.expects.clone() },
    )?;
    let state = notify::ensure_inbox(&app.cfg);
    // The same title returns the same task; it must not return the same toast.
    if app.db.mark_notified(&t.id).unwrap_or(true) {
        notify::desktop(&app.cfg, &t.title, &format!("{} · {agent}", tokenstash_core::project::short(&project)), &util::inbox_notice(&app.cfg, Some(&t.id), state));
    }
    let mut task = t;
    if a.blocking {
        let start = std::time::Instant::now();
        while task.status == tokenstash_core::db::TaskStatus::Pending && start.elapsed().as_secs() < a.timeout {
            std::thread::sleep(Duration::from_millis(500));
            app.db.expire_overdue()?;
            task = app.db.get_task(&task.id)?.unwrap_or(task);
        }
    }
    let state = notify::inbox_state(&app.cfg);
    if a.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "task": task, "inbox": util::inbox_url_agent(&app.cfg, Some(&task.id), state) }))?);
    } else {
        println!("{} {} — task {} → {}", status_icon(&task.status), task.title, task.id, util::inbox_url_agent(&app.cfg, Some(&task.id), state));
        if let Some(n) = &task.note {
            println!("  note: {n}");
        }
    }
    Ok(match task.status {
        tokenstash_core::db::TaskStatus::Pending => exit::PENDING,
        tokenstash_core::db::TaskStatus::Answered => exit::INJECTED,
        tokenstash_core::db::TaskStatus::Denied => exit::DENIED,
        tokenstash_core::db::TaskStatus::Expired => exit::EXPIRED,
    })
}

pub fn status_icon(s: &tokenstash_core::db::TaskStatus) -> &'static str {
    use tokenstash_core::db::TaskStatus::*;
    match s {
        Pending => "⏳",
        Answered => "✓",
        Denied => "✗",
        Expired => "⌛",
    }
}
