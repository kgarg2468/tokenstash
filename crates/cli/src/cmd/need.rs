use crate::notify;
use crate::util::{self, App};
use anyhow::Result;
use clap::Args;
use std::path::PathBuf;
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
    #[arg(long, default_value = "600")]
    pub timeout: u64,
    /// Project directory (defaults to cwd / git root).
    #[arg(long)]
    pub project: Option<PathBuf>,
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
    let app = App::open()?;
    let project = util::project_from(&a.project);
    let agent = util::agent_from(&a.agent);
    let opts = NeedOpts {
        req: SecretRequest { why: a.why.clone(), url: a.url.clone(), steps: a.steps.clone(), pattern: a.pattern.clone() },
        identity: a.identity.clone(),
        blocking: false,
        timeout: Duration::from_secs(a.timeout),
        force: a.force,
    };
    let mut outcomes = need::need(&app.ctx(), &project, &agent, &a.names, &opts)?;

    if outcomes.iter().any(|o| o.is_pending()) {
        notify_pending(&app, &project, &agent, &outcomes);
        if a.blocking {
            let blocking = NeedOpts { blocking: true, ..opts.clone() };
            // re-run to wait (hits are idempotent; pending tasks are reused)
            outcomes = need::need(&app.ctx(), &project, &agent, &a.names, &blocking)?;
        }
    }

    if a.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "project": project,
            "env_file": app.cfg.env_file,
            "inbox": util::inbox_url(&app.cfg, None),
            "results": outcomes,
        }))?);
    } else {
        for o in &outcomes {
            match o {
                Outcome::Injected { name, written_to, generated, .. } => {
                    let p = std::path::Path::new(written_to);
                    let rel = p.strip_prefix(&project).map(|r| r.display().to_string()).unwrap_or(written_to.clone());
                    println!("✓ {name} {} → {rel}", if *generated { "generated and injected" } else { "injected" });
                }
                Outcome::Pending { name, task_id, .. } => {
                    println!("⏳ {name} pending — task {task_id} → {}", util::inbox_url(&app.cfg, Some(task_id)));
                }
                Outcome::Denied { name, .. } => println!("✗ {name} denied by the user — do not ask again; work around it"),
                Outcome::Expired { name, .. } => println!("✗ {name} expired unanswered"),
            }
        }
        if outcomes.iter().any(|o| o.is_pending()) {
            eprintln!("\nThe human has been notified. Continue with other work; re-run this command or `tokenstash tasks` to check.");
        }
    }
    Ok(code_for(&outcomes))
}

pub fn notify_pending(app: &App, project: &std::path::Path, agent: &str, outcomes: &[Outcome]) {
    notify::ensure_inbox(&app.cfg);
    let pending: Vec<&str> = outcomes.iter().filter(|o| o.is_pending()).map(|o| o.name()).collect();
    let first_id = outcomes.iter().find_map(|o| match o { Outcome::Pending { task_id, .. } => Some(task_id.clone()), _ => None });
    let link = crate::notify::verified_inbox_link(&app.cfg, first_id.as_deref()).unwrap_or_else(|| "start it from a terminal: `tokenstash open`".into());
    notify::desktop(
        &app.cfg,
        &format!("{} needs {}", tokenstash_core::project::short(project), pending.join(", ")),
        &format!("requested by {agent}"),
        &link,
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
    /// confirm | text
    #[arg(long, default_value = "confirm")]
    pub expects: String,
    #[arg(long)]
    pub blocking: bool,
    #[arg(long, default_value = "600")]
    pub timeout: u64,
    #[arg(long)]
    pub project: Option<PathBuf>,
    #[arg(long)]
    pub agent: Option<String>,
    #[arg(long)]
    pub json: bool,
}

pub fn ask(a: AskArgs) -> Result<i32> {
    let app = App::open()?;
    let project = util::project_from(&a.project);
    let agent = util::agent_from(&a.agent);
    let t = tasks::create_human_task(
        &app.ctx(),
        &project,
        &agent,
        HumanRequest { title: a.title.clone(), why: a.why.clone(), url: a.url.clone(), steps: a.steps.clone(), expects: a.expects.clone() },
    )?;
    notify::ensure_inbox(&app.cfg);
    let link = crate::notify::verified_inbox_link(&app.cfg, Some(&t.id)).unwrap_or_else(|| "start it from a terminal: `tokenstash open`".into());
    notify::desktop(&app.cfg, &t.title, &format!("{} · {agent}", tokenstash_core::project::short(&project)), &link);
    let mut task = t;
    if a.blocking {
        let start = std::time::Instant::now();
        while task.status == tokenstash_core::db::TaskStatus::Pending && start.elapsed().as_secs() < a.timeout {
            std::thread::sleep(Duration::from_millis(500));
            app.db.expire_overdue()?;
            task = app.db.get_task(&task.id)?.unwrap_or(task);
        }
    }
    if a.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "task": task, "inbox": util::inbox_url(&app.cfg, Some(&task.id)) }))?);
    } else {
        println!("{} {} — task {} → {}", status_icon(&task.status), task.title, task.id, util::inbox_url(&app.cfg, Some(&task.id)));
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
