//! Task lifecycle: create (secret / approval / human), answer, deny, expire.
//! Answering a secret task is the only place a value enters the system: validate → store → inject.

use crate::db::{Task, TaskKind, TaskStatus};
use crate::stash::{stash_key, Stash};
use crate::validate::{self, Liveness};
use crate::{registry, Config, Db};
use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use std::path::{Path, PathBuf};

/// Minimum accepted length for a pasted secret.
pub const MIN_SECRET_CHARS: usize = 6;

pub struct Ctx<'a> {
    pub cfg: &'a Config,
    pub db: &'a Db,
    pub stash: &'a dyn Stash,
}

pub fn new_id(prefix: &str) -> String {
    let n: u32 = rand::thread_rng().gen_range(0..0xFFFFFF);
    format!("{prefix}_{n:06x}")
}

pub fn deadline(cfg: &Config) -> String {
    (chrono::Utc::now() + chrono::Duration::hours(cfg.task_ttl_hours as i64))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[derive(Debug, Default, Clone)]
pub struct SecretRequest {
    pub why: Option<String>,
    pub url: Option<String>,
    pub steps: Vec<String>,
    pub pattern: Option<String>,
}

/// Create (or reuse the open) secret task for `name` in `project`. Registry fills in gaps.
pub fn create_secret_task(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, req: &SecretRequest) -> Result<Task> {
    let pid = project.to_string_lossy().to_string();
    if let Some(t) = ctx.db.open_secret_task(&pid, name, identity)? {
        return Ok(t);
    }
    let p = registry::lookup(name);
    let title = match p {
        Some(p) => format!("{} API key ({})", p.provider, name),
        None => format!("Provide {name}"),
    };
    let t = Task {
        id: new_id("t"),
        kind: TaskKind::Secret,
        project: pid.clone(),
        agent: agent.into(),
        name: Some(name.into()),
        identity: identity.into(),
        title,
        why: req.why.clone(),
        url: req.url.clone().or_else(|| p.map(|p| p.url.clone())),
        steps: if !req.steps.is_empty() { req.steps.clone() } else { p.map(|p| p.steps.clone()).unwrap_or_default() },
        expects: "secret".into(),
        pattern: req.pattern.clone().or_else(|| p.and_then(|p| p.pattern.clone())),
        names: vec![],
        status: TaskStatus::Pending,
        created: crate::now(),
        deadline: deadline(ctx.cfg),
        answered_at: None,
        note: None,
    };
    ctx.db.insert_task(&t)?;
    ctx.db.audit(Some(&pid), Some(agent), "task.secret", Some(name), Some(identity), None)?;
    Ok(t)
}

/// Split an approval entry `NAME@identity` (identity defaults to "default").
pub fn split_identity(entry: &str) -> (&str, &str) {
    match entry.split_once('@') {
        Some((n, i)) if !i.is_empty() => (n, i),
        _ => (entry, "default"),
    }
}

/// Create or merge into the open approval task for this project.
/// `names` are `NAME@identity` entries and may include "*" meaning "this project is
/// outside trust roots".
pub fn create_approval_task(ctx: &Ctx, project: &Path, agent: &str, names: &[String]) -> Result<Task> {
    let pid = project.to_string_lossy().to_string();
    if let Some(mut t) = ctx.db.open_approval_task(&pid)? {
        let mut merged = t.names.clone();
        for n in names {
            if !merged.contains(n) {
                merged.push(n.clone());
            }
        }
        if merged != t.names {
            ctx.db.update_task_names(&t.id, &merged)?;
            t.names = merged;
        }
        return Ok(t);
    }
    let outside = names.iter().any(|n| n == "*");
    let concrete: Vec<&String> = names.iter().filter(|n| n.as_str() != "*").collect();
    let _ = &concrete;
    let title = if outside {
        format!("Allow {} to use {} key(s)?", crate::project::short(project), concrete.len())
    } else {
        format!("Allow {} to use sensitive key(s)?", crate::project::short(project))
    };
    let why = if outside {
        Some("This project is outside your trust roots.".to_string())
    } else {
        Some("These keys are tagged sensitive (live payments, cloud credentials, or unbounded spend).".to_string())
    };
    let t = Task {
        id: new_id("a"),
        kind: TaskKind::Approval,
        project: pid.clone(),
        agent: agent.into(),
        name: None,
        identity: "default".into(),
        title,
        why,
        url: None,
        steps: vec![],
        expects: "confirm".into(),
        pattern: None,
        names: names.to_vec(),
        status: TaskStatus::Pending,
        created: crate::now(),
        deadline: deadline(ctx.cfg),
        answered_at: None,
        note: None,
    };
    ctx.db.insert_task(&t)?;
    ctx.db.audit(Some(&pid), Some(agent), "task.approval", None, None, Some(&names.join(",")))?;
    Ok(t)
}

pub struct HumanRequest {
    pub title: String,
    pub why: Option<String>,
    pub url: Option<String>,
    pub steps: Vec<String>,
    /// "confirm" | "text" | "choice"
    pub expects: String,
}

pub fn create_human_task(ctx: &Ctx, project: &Path, agent: &str, req: HumanRequest) -> Result<Task> {
    let pid = project.to_string_lossy().to_string();
    let t = Task {
        id: new_id("h"),
        kind: TaskKind::Human,
        project: pid.clone(),
        agent: agent.into(),
        name: None,
        identity: "default".into(),
        title: req.title,
        why: req.why,
        url: req.url,
        steps: req.steps,
        expects: req.expects,
        pattern: None,
        names: vec![],
        status: TaskStatus::Pending,
        created: crate::now(),
        deadline: deadline(ctx.cfg),
        answered_at: None,
        note: None,
    };
    ctx.db.insert_task(&t)?;
    ctx.db.audit(Some(&pid), Some(agent), "task.human", None, None, Some(&t.title))?;
    Ok(t)
}

#[derive(Debug)]
pub enum AnswerResult {
    Stored { injected_to: Option<PathBuf>, sensitive: bool, liveness: Option<Liveness> },
    Approved { injected: Vec<String> },
    Denied,
    Done,
}

/// Store a secret value for a task: pattern → liveness → stash → index → inject → audit.
pub fn answer_secret(ctx: &Ctx, task: &Task, value: SecretString, skip_liveness: bool) -> Result<AnswerResult> {
    if task.kind != TaskKind::Secret {
        bail!("task {} is not a secret task", task.id);
    }
    if task.status != TaskStatus::Pending {
        bail!("task {} is already {}", task.id, task.status.as_str());
    }
    let name = task.name.clone().ok_or_else(|| anyhow!("secret task without name"))?;
    // No real credential is this short. Refusing here keeps trivially short strings out of
    // the stash entirely, so the redactor never has to special-case them.
    if value.expose_secret().chars().count() < MIN_SECRET_CHARS {
        bail!("value is shorter than {MIN_SECRET_CHARS} characters; that is not a credential. Not stored.");
    }
    if let Some(p) = &task.pattern {
        if !validate::matches_pattern(p, &value)? {
            bail!("value does not match the expected pattern for {name} ({p}). Not stored.");
        }
    }
    let provider = registry::lookup(&name);
    let mut liveness = None;
    if !skip_liveness {
        if let Some(check) = provider.and_then(|p| p.check.as_ref()) {
            let l = validate::liveness(check, &value);
            if let Liveness::Rejected(code) = l {
                bail!("{} rejected this key (HTTP {code}). Not stored. Re-run with --skip-check to store anyway.", provider.map(|p| p.provider.as_str()).unwrap_or("provider"));
            }
            liveness = Some(l);
        }
    }
    let sensitive = provider.map(|p| p.sensitive).unwrap_or(false)
        || match provider.and_then(|p| p.sensitive_pattern.as_ref()) {
            Some(sp) => validate::matches_pattern(sp, &value)?,
            None => false,
        };
    let injected_to = store_and_inject(
        ctx, &name, &task.identity, &value, provider.map(|p| p.provider.clone()), task.url.clone(), sensitive,
        Path::new(&task.project), &task.agent, Some(&task.id),
    )?;
    Ok(AnswerResult::Stored { injected_to, sensitive, liveness })
}

/// Shared by `answer_secret` and auto-generated secrets.
///
/// Order matters: keychain first (the value's home), then ONE transaction that records the
/// index entry, the project approval, the audit row, and — when answering a task — the
/// task's answered status. Injection into the env file happens last; if it fails the task
/// is already answered and the value already stored, so a re-run of `need` hits and
/// injects rather than asking the human again.
#[allow(clippy::too_many_arguments)]
pub fn store_and_inject(
    ctx: &Ctx,
    name: &str,
    identity: &str,
    value: &SecretString,
    provider: Option<String>,
    source_url: Option<String>,
    sensitive: bool,
    project: &Path,
    agent: &str,
    answering_task: Option<&str>,
) -> Result<Option<PathBuf>> {
    ctx.stash.set(&stash_key(name, identity), value)?;
    let pid = project.to_string_lossy().to_string();
    let tx = ctx.db.conn.unchecked_transaction()?;
    ctx.db.upsert_secret(&crate::db::SecretMeta {
        name: name.into(),
        identity: identity.into(),
        provider,
        sensitive,
        source_url,
        created: crate::now(),
        last_used: Some(crate::now()),
        stale: false,
    })?;
    ctx.db.audit(Some(&pid), Some(agent), "store", Some(name), Some(identity), None)?;
    // The human just handled this key for this project: that is the approval.
    ctx.db.approve(&pid, name)?;
    if let Some(tid) = answering_task {
        ctx.db.set_task_status(tid, TaskStatus::Answered, None)?;
    }
    tx.commit().context("recording the stored secret")?;
    let injected_to = if project.is_dir() {
        let p = crate::envfile::write(project, &ctx.cfg.env_file, name, value)?;
        ctx.db.audit(Some(&pid), Some(agent), "inject", Some(name), Some(identity), None)?;
        Some(p)
    } else {
        None
    };
    Ok(injected_to)
}

pub fn answer_approval(ctx: &Ctx, task: &Task, allow: bool) -> Result<AnswerResult> {
    if task.kind != TaskKind::Approval {
        bail!("task {} is not an approval task", task.id);
    }
    if task.status != TaskStatus::Pending {
        bail!("task {} is already {}", task.id, task.status.as_str());
    }
    let pid = task.project.clone();
    if !allow {
        ctx.db.set_task_status(&task.id, TaskStatus::Denied, None)?;
        ctx.db.audit(Some(&pid), Some(&task.agent), "deny", None, None, Some(&task.names.join(",")))?;
        return Ok(AnswerResult::Denied);
    }
    let project = Path::new(&pid);
    let mut injected = vec![];
    for entry in &task.names {
        if entry == "*" {
            ctx.db.approve(&pid, "*")?;
            continue;
        }
        // Inject exactly the identity that was requested; approval is recorded per name.
        let (n, identity) = split_identity(entry);
        ctx.db.approve(&pid, n)?;
        if let Some(v) = ctx.stash.get(&stash_key(n, identity))? {
            if project.is_dir() {
                crate::envfile::write(project, &ctx.cfg.env_file, n, &v)?;
                ctx.db.touch_secret(n, identity)?;
                ctx.db.audit(Some(&pid), Some(&task.agent), "inject", Some(n), Some(identity), Some("after-approval"))?;
                injected.push(n.to_string());
            }
        }
    }
    ctx.db.set_task_status(&task.id, TaskStatus::Answered, None)?;
    ctx.db.audit(Some(&pid), Some(&task.agent), "approve", None, None, Some(&task.names.join(",")))?;
    Ok(AnswerResult::Approved { injected })
}

pub fn answer_human(ctx: &Ctx, task: &Task, note: Option<&str>) -> Result<AnswerResult> {
    if task.kind != TaskKind::Human {
        bail!("task {} is not a human task", task.id);
    }
    // Text answers are returned to the agent and shown in task history. A credential must
    // never travel that path; refuse it here rather than trying to redact it later.
    if let Some(n) = note {
        if validate::looks_like_secret(n) {
            bail!("that answer looks like a credential; it would be shown to the agent. Decline this task and have the agent request it with `tokenstash need NAME` instead.");
        }
    }
    ctx.db.set_task_status(&task.id, TaskStatus::Answered, note)?;
    ctx.db.audit(Some(&task.project), Some(&task.agent), "human.done", None, None, Some(&task.title))?;
    Ok(AnswerResult::Done)
}

pub fn deny(ctx: &Ctx, task: &Task, note: Option<&str>) -> Result<AnswerResult> {
    ctx.db.set_task_status(&task.id, TaskStatus::Denied, note)?;
    ctx.db.audit(Some(&task.project), Some(&task.agent), "deny", task.name.as_deref(), None, None)?;
    Ok(AnswerResult::Denied)
}

pub fn expire(ctx: &Ctx) -> Result<usize> {
    ctx.db.expire_overdue()
}
