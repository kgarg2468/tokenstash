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
    /// How a liveness probe reaches the provider. `Network` in the binary; tests must use
    /// `Off` or `Stub` — a unit test that sends a canary to api.openai.com is a bug.
    pub probe: Probe<'a>,
}

/// The one seam between tokenstash and the provider's HTTP endpoint.
#[derive(Clone, Copy)]
pub enum Probe<'a> {
    Network,
    /// No probe ever runs (tests, or callers that must stay offline).
    Off,
    /// A canned verdict (tests). Receives the check so a test can assert which one ran.
    Stub(&'a dyn Fn(&crate::registry::Check) -> Liveness),
}

impl Probe<'_> {
    /// `None` when probing is off. Never logs the value.
    pub fn run(&self, check: &crate::registry::Check, value: &SecretString, timeout: std::time::Duration) -> Option<Liveness> {
        let _ = (value, timeout);
        match self {
            #[cfg(test)]
            Probe::Network => panic!("unit tests must not probe the network: use Probe::Off or Probe::Stub"),
            #[cfg(not(test))]
            Probe::Network => Some(validate::liveness(check, value, timeout)),
            Probe::Off => None,
            Probe::Stub(f) => Some(f(check)),
        }
    }
}

/// What the human-side store knows about the value it is storing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    /// The provider accepted it just now.
    Ok,
    /// No probe exists, or it could not be reached: unknown, verify-on-use stays on.
    Unknown,
    /// The human chose to skip the check: verify-on-use is off for this key until a probe
    /// says Ok, so a probe that would keep rejecting cannot keep filing cards.
    Skipped,
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
    create_secret_task_kind(ctx, project, agent, name, identity, req, "secret")
}

/// A replacement card for a stale key: same shape, marked so its answer propagates.
pub fn create_replacement_task(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, req: &SecretRequest) -> Result<Task> {
    create_secret_task_kind(ctx, project, agent, name, identity, req, EXPECTS_REPLACE)
}

fn create_secret_task_kind(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, req: &SecretRequest, expects: &str) -> Result<Task> {
    let pid = project.to_string_lossy().to_string();
    if let Some(t) = ctx.db.open_secret_task(&pid, name, identity)? {
        // An ordinary card reused for a replacement must carry the marker, or its answer
        // would not propagate; the reverse never downgrades.
        if expects == EXPECTS_REPLACE && t.expects != EXPECTS_REPLACE {
            ctx.db.set_task_expects(&t.id, EXPECTS_REPLACE)?;
            return Ok(Task { expects: EXPECTS_REPLACE.into(), ..t });
        }
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
        expects: expects.into(),
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
    create_approval_task_opts(ctx, project, agent, names, true)
}

/// `merge=false` always files a fresh task: used for program-derived requests, where each
/// invocation must be authorized on its own and must not piggyback on (or be granted by)
/// another invocation's pending approval.
/// Marker in `expects` for a secret task that REPLACES a stale value (a rotation or a
/// reported-dead key). Only answers to such cards propagate to other projects; an ordinary
/// paste card answered later, even if the key has since gone stale elsewhere, does not.
pub const EXPECTS_REPLACE: &str = "replace";

/// Marker in `expects` for an approval that must not become a standing grant: a program's
/// own output chose the key (`run` shim), so the human authorises THIS injection only.
pub const APPROVAL_ONCE: &str = "once";

pub fn create_approval_task_opts(ctx: &Ctx, project: &Path, agent: &str, names: &[String], merge: bool) -> Result<Task> {
    let pid = project.to_string_lossy().to_string();
    if let Some(mut t) = ctx.db.open_approval_task(&pid)?.filter(|_| merge) {
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
        expects: if merge { "confirm".into() } else { APPROVAL_ONCE.into() },
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
    Stored { injected_to: Option<PathBuf>, sensitive: bool, liveness: Option<Liveness>, rotation: Option<RotationReport> },
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
            if let Some(l) = ctx.probe.run(check, &value, validate::TIMEOUT_HUMAN) {
                if let Liveness::Rejected(code) = l {
                    bail!("{} rejected this key (HTTP {code}). Not stored. Re-run with --skip-check to store anyway.", provider.map(|p| p.provider.as_str()).unwrap_or("provider"));
                }
                liveness = Some(l);
            }
        }
    }
    let sensitive = provider.map(|p| p.sensitive).unwrap_or(false)
        || match provider.and_then(|p| p.sensitive_pattern.as_ref()) {
            Some(sp) => validate::matches_pattern(sp, &value)?,
            None => false,
        };
    // Rotation: when a STALE key is being replaced, remember the value so every other project
    // still holding it can be rewritten below. An ordinary paste that happens to differ from
    // a stored value (two projects with their own pending cards) is not a rotation.
    let is_replacement = task.expects == EXPECTS_REPLACE;
    let injected_to = store_and_inject(
        ctx, &name, &task.identity, &value, provider.map(|p| p.provider.clone()), task.url.clone(), sensitive,
        Path::new(&task.project), &task.agent, Some(&task.id),
        match liveness { Some(Liveness::Ok) => Verified::Ok, _ if skip_liveness => Verified::Skipped, _ => Verified::Unknown },
    )?;
    // A replacement card's answer reaches every project that was ever given this key and
    // does not already hold the new value — whichever old value it holds (the stash may
    // have changed between the stale mark and this answer).
    let rotation = if is_replacement { Some(rewrite_replaced_value(ctx, &name, &task.identity, &value, &task.project)?) } else { None };
    Ok(AnswerResult::Stored { injected_to, sensitive, liveness, rotation })
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
    verified: Verified,
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
        last_verified: if verified == Verified::Ok { Some(crate::now()) } else { None },
        stale_reason: None,
        stale_source: None,
        next_probe: None,
        verify_off: verified == Verified::Skipped,
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
    // 1. Record the decision atomically: every approval plus the task's answered status.
    //    Once this commits the human's answer is final and nothing can ask them again.
    //    A one-time approval (program-derived, `run`) records the answer but no grant: the
    //    next request for the same key in this project asks again, by design.
    {
        let tx = ctx.db.conn.unchecked_transaction()?;
        if task.expects != APPROVAL_ONCE {
            for entry in &task.names {
                let n = if entry == "*" { "*" } else { split_identity(entry).0 };
                ctx.db.approve(&pid, n)?;
            }
        }
        ctx.db.set_task_status(&task.id, TaskStatus::Answered, None)?;
        ctx.db.audit(Some(&pid), Some(&task.agent), "approve", None, None, Some(&task.names.join(",")))?;
        tx.commit().context("recording approval")?;
    }
    // 2. Inject each requested identity. Failures are collected and surfaced after all
    //    entries are attempted; the approval itself is already recorded.
    let mut injected = vec![];
    let mut failures = vec![];
    let mut budget = crate::need::ProbeBudget::default();
    for entry in &task.names {
        if entry == "*" {
            continue;
        }
        let (n, identity) = split_identity(entry);
        if let Some(v) = ctx.stash.get(&stash_key(n, identity))? {
            if project.is_dir() {
                // The approval is the authorization; delivery still verifies on use. A key
                // the provider rejects becomes a Replace card for this project instead of
                // a dead value in its env file.
                match crate::need::deliver(ctx, project, &task.agent, n, identity, &v, Some("after-approval"), &mut budget) {
                    Ok(crate::need::Delivery::Injected { .. }) => injected.push(n.to_string()),
                    Ok(crate::need::Delivery::Rejected { reason }) => {
                        let why = format!("Replace {n}: {reason}. The new value is written to {}.", project.join(&ctx.cfg.env_file).display());
                        let req = SecretRequest { why: Some(why), ..Default::default() };
                        create_replacement_task(ctx, project, &task.agent, n, identity, &req)?;
                        failures.push(format!("{n}: {reason} — a replacement card has been filed"));
                    }
                    Err(e) => failures.push(format!("{n}: {e:#}")),
                }
            }
        }
    }
    if !failures.is_empty() {
        bail!("approval recorded, but injection failed for {}. Re-run `need`; it will inject from the stash without asking again.", failures.join("; "));
    }
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

/// After a key is replaced, every other project that was given this key and whose env
/// file does not already hold the NEW value gets it — otherwise each of them fails next
/// week and files its own card. The comparison happens here, value to value, and is never
/// shown. Projects that no longer exist, or no longer have the variable at all, are left
/// alone.
/// What the post-rotation rewrite did, for the human: the projects updated and the ones
/// that still hold the old value and why (a git-tracked env file, a permission error).
/// Those need a hand before the old key is revoked.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RotationReport {
    pub rewritten: Vec<String>,
    pub skipped: Vec<(String, String)>,
}

pub fn rewrite_replaced_value(ctx: &Ctx, name: &str, identity: &str, new: &SecretString, answering_project: &str) -> Result<RotationReport> {
    let mut report = RotationReport::default();
    let sensitive = ctx.db.get_secret(name, identity)?.map(|m| m.sensitive).unwrap_or(false);
    for project in ctx.db.delivered_projects(name, identity)? {
        if project == answering_project {
            continue;
        }
        let dir = Path::new(&project);
        if !dir.is_dir() {
            continue;
        }
        // A past delivery is not a standing grant: a project that only ever had a one-time
        // (run-shim) approval, or has since left the trust roots, must pass the gate again.
        if !matches!(crate::trust::gate(ctx.db, ctx.cfg, dir, name, sensitive)?, crate::trust::Gate::Open) {
            let why = "no standing approval for this key here; it will ask on its next `need`".to_string();
            ctx.db.audit(Some(&project), None, "rotate.skip", Some(name), Some(identity), Some(&why))?;
            report.skipped.push((project.clone(), why));
            continue;
        }
        let Ok(env_path) = crate::envfile::resolve(dir, &ctx.cfg.env_file) else { continue };
        let Ok(text) = std::fs::read_to_string(&env_path) else { continue };
        let needs_update = text.lines().filter_map(crate::envfile::parse_line).any(|(k, v)| k == name && v != new.expose_secret());
        if !needs_update {
            continue;
        }
        match crate::envfile::write(dir, &ctx.cfg.env_file, name, new) {
            Ok(_) => {
                ctx.db.audit(Some(&project), None, "inject", Some(name), Some(identity), Some("after-rotation"))?;
                report.rewritten.push(project.clone());
            }
            Err(e) => {
                let why = format!("{e:#}");
                ctx.db.audit(Some(&project), None, "rotate.skip", Some(name), Some(identity), Some(&why))?;
                report.skipped.push((project.clone(), why));
            }
        }
    }
    Ok(report)
}

/// The human asked to replace a key: mark it stale and file the replacement card now.
pub fn rotate(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str) -> Result<Task> {
    let pid = project.to_string_lossy().to_string();
    if ctx.db.get_secret(name, identity)?.is_none() {
        bail!("{name}@{identity} is not in the stash; use `tokenstash need {name}` to add it");
    }
    ctx.db.mark_stale(name, identity, true, Some(crate::db::Db::ROTATE_REASON), Some(crate::db::STALE_ROTATE))?;
    ctx.db.audit(Some(&pid), Some(agent), "rotate", Some(name), Some(identity), None)?;
    let req = SecretRequest { why: Some(format!("Replace {name}: {}. Paste the new key first, then revoke the old one in the dashboard.", crate::db::Db::ROTATE_REASON)), ..Default::default() };
    create_replacement_task(ctx, project, agent, name, identity, &req)
}

/// What a report changed. Never returned to the agent (see `report_bad`); for tests and
/// the CLI's own output.
#[derive(Debug, Clone, PartialEq)]
pub enum ReportOutcome {
    /// Not delivered here, on cooldown, unknown: nothing changed.
    Ignored,
    /// The registry probe accepted the key: the report was wrong.
    FalseReport,
    /// Marked stale (by probe verdict, or by the report when no probe exists).
    MarkedStale,
}

/// An agent says a provider rejected a key. The agent is the only sensor tokenstash has —
/// it is never in the request path — but its word is a claim, not a verdict:
/// - only a project that actually received the key can report it (otherwise: ignored, and
///   the caller cannot tell — no stash-existence oracle);
/// - when the registry has a liveness check, the probe decides: a hostile repo cannot make
///   the provider reject a live key;
/// - one report per (project, key) per task_ttl_hours; a probe that says Ok records a
///   false report and further reports are ignored for the window.
///
/// The replacement card always names the reporting project and agent.
pub fn report_bad(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, status: Option<u16>) -> Result<ReportOutcome> {
    let pid = project.to_string_lossy().to_string();
    if !ctx.db.has_delivered(&pid, name, identity)? {
        return Ok(ReportOutcome::Ignored);
    }
    let Some(meta) = ctx.db.get_secret(name, identity)? else { return Ok(ReportOutcome::Ignored) };
    if meta.stale {
        return Ok(ReportOutcome::Ignored); // already a miss; nothing to add
    }
    // One report per (project, key) per TTL — but a report made BEFORE the current value
    // was stored is about a previous value and must not shadow a report about this one.
    let ttl_since = (chrono::Utc::now() - chrono::Duration::hours(ctx.cfg.task_ttl_hours as i64)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let since = if meta.created > ttl_since { meta.created.clone() } else { ttl_since };
    if ctx.db.recent_report(&pid, name, identity, &since)?.is_some() {
        return Ok(ReportOutcome::Ignored);
    }
    // Only the status is recorded. The provider's message is agent-controlled text that may
    // echo a key (this one, or a previous one the redactor no longer knows); nothing from it
    // is persisted or shown.
    let detail = format!("HTTP {}", status.map(|s| s.to_string()).unwrap_or_else(|| "?".into()));
    let provider = registry::lookup(name);
    let value = ctx.stash.get(&stash_key(name, identity))?;
    let has_check = provider.and_then(|p| p.check.as_ref()).is_some();
    let verdict = match (provider.and_then(|p| p.check.as_ref()), value.as_ref()) {
        (Some(check), Some(v)) => ctx.probe.run(check, v, validate::TIMEOUT_HUMAN),
        _ => None,
    };
    let date = crate::now();
    match verdict {
        Some(Liveness::Ok) => {
            ctx.db.set_verified(name, identity)?;
            ctx.db.audit(Some(&pid), Some(agent), "false_report", Some(name), Some(identity), Some(&detail))?;
            Ok(ReportOutcome::FalseReport)
        }
        Some(Liveness::Rejected(code)) => {
            let reason = format!("rejected by {} (HTTP {code}) on {date}, reported by {agent} in {}", provider.map(|p| p.provider.as_str()).unwrap_or("the provider"), crate::project::short(project));
            ctx.db.mark_stale(name, identity, true, Some(&reason), Some(crate::db::STALE_REPORT))?;
            ctx.db.audit(Some(&pid), Some(agent), "report", Some(name), Some(identity), Some(&detail))?;
            Ok(ReportOutcome::MarkedStale)
        }
        // The provider has a probe but it could not be reached: no verdict, no change. The
        // agent retries later; the human is not asked on the strength of an offline report.
        Some(Liveness::Unknown(_)) => {
            ctx.db.audit(Some(&pid), Some(agent), "report.unverified", Some(name), Some(identity), Some(&detail))?;
            Ok(ReportOutcome::Ignored)
        }
        // No probe exists for this provider: the report stands, and the card says exactly
        // who made it and that it is unverified.
        None if !has_check => {
            let reason = format!("reported rejected ({detail}) on {date} by {agent} in {} — unverified (no liveness check for this provider)", crate::project::short(project));
            ctx.db.mark_stale(name, identity, true, Some(&reason), Some(crate::db::STALE_REPORT))?;
            ctx.db.audit(Some(&pid), Some(agent), "report", Some(name), Some(identity), Some(&detail))?;
            Ok(ReportOutcome::MarkedStale)
        }
        None => Ok(ReportOutcome::Ignored),
    }
}
