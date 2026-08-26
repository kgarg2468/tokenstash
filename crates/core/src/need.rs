//! `need`: the one call an agent makes. Hit → inject silently (unless gated). Miss → file a task.

use crate::db::TaskStatus;
use crate::stash::stash_key;
use crate::tasks::{self, Ctx, SecretRequest};
use crate::trust::{self, Gate, GateReason};
use crate::registry;
use crate::validate::Liveness;
use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct NeedOpts {
    pub req: SecretRequest,
    pub identity: Option<String>,
    pub blocking: bool,
    pub timeout: Duration,
    /// Ask again even if the user recently denied this key for this project.
    pub force: bool,
    /// Never inject silently: route every hit through a fresh approval task, even if this
    /// project was approved before. Used when the request was derived from untrusted input
    /// (a program's output in `run`) — each invocation needs its own human yes.
    pub require_approval: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    /// `unverified`: the key has a registry probe that was due but could not run (provider
    /// unreachable, rate-limited, or the per-call probe budget was spent). Delivered anyway.
    Injected { name: String, identity: String, written_to: String, generated: bool, unverified: bool },
    Pending { name: String, identity: String, task_id: String, title: String, url: Option<String> },
    Denied { name: String, task_id: String },
    Expired { name: String, task_id: String },
}

impl Outcome {
    pub fn name(&self) -> &str {
        match self {
            Outcome::Injected { name, .. } | Outcome::Pending { name, .. } | Outcome::Denied { name, .. } | Outcome::Expired { name, .. } => name,
        }
    }
    pub fn is_pending(&self) -> bool {
        matches!(self, Outcome::Pending { .. })
    }
}

/// Auto-generate local secrets (session secrets etc.) instead of asking a human.
fn generate(spec: &str) -> Option<SecretString> {
    use rand::RngCore;
    let (kind, n) = spec.split_once(':')?;
    let n: usize = n.parse().ok()?;
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    let s = match kind {
        "base64" => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        }
        "hex" => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        _ => return None,
    };
    Some(SecretString::from(s))
}

pub fn need(ctx: &Ctx, project: &Path, agent: &str, names: &[String], opts: &NeedOpts) -> Result<Vec<Outcome>> {
    need_with_budget(ctx, project, agent, names, opts, &mut ProbeBudget::default())
}

/// `need` with a caller-owned probe budget, for callers that issue several `need`s in one
/// request (the MCP server, one per name) and must not pay one timeout per name offline.
pub fn need_with_budget(ctx: &Ctx, project: &Path, agent: &str, names: &[String], opts: &NeedOpts, budget: &mut ProbeBudget) -> Result<Vec<Outcome>> {
    ctx.db.expire_overdue()?;
    // Approvals, bindings, and tasks are keyed by the resolved path, so a symlink that is
    // later retargeted cannot inherit another project's approval.
    let project = &project.canonicalize().with_context(|| format!("project directory {} does not exist", project.display()))?;
    let pid = project.to_string_lossy().to_string();
    let mut outcomes: Vec<Outcome> = Vec::with_capacity(names.len());
    let mut gated: Vec<String> = vec![];
    let mut outside = false;

    for name in names {
        let identity = opts
            .identity
            .clone()
            .or(ctx.db.binding(&pid, name)?)
            .unwrap_or_else(|| "default".into());
        let provider = registry::lookup(name);
        let hit = ctx.stash.get(&stash_key(name, &identity))?;

        if let Some(value) = hit {
            let mut meta = ctx.db.get_secret(name, &identity)?;
            if meta.is_none() {
                // The stash is per-user; this index is per-TOKENSTASH_HOME. A key stored under
                // another home is real and usable, but `list` here would deny it exists —
                // a stash that says "empty" and then injects is the worst kind of surprise.
                // Adopt it into this index, visibly, before anything else happens.
                let m = crate::db::SecretMeta {
                    name: name.clone(),
                    identity: identity.clone(),
                    provider: provider.map(|p| p.provider.clone()),
                    sensitive: provider.map(|p| p.sensitive).unwrap_or(false),
                    source_url: provider.map(|p| p.url.clone()),
                    created: crate::now(),
                    last_used: None,
                    stale: false,
                    last_verified: None,
                    stale_reason: None,
                    stale_source: None,
                    next_probe: None,
                    verify_off: false,
                };
                ctx.db.upsert_secret(&m)?;
                ctx.db.audit(Some(&pid), Some(agent), "adopt", Some(name), Some(&identity), Some("found in the stash but not in this home's index"))?;
                meta = Some(m);
            }
            let sensitive = meta.as_ref().map(|m| m.sensitive).unwrap_or_else(|| provider.map(|p| p.sensitive).unwrap_or(false));
            let gate = if opts.require_approval {
                Gate::NeedsApproval { reason: GateReason::Sensitive }
            } else {
                trust::gate(ctx.db, ctx.cfg, project, name, sensitive)?
            };
            match gate {
                // A stale key is a miss, but only once the project has passed the same gate a
                // fresh injection would: a project that would need approval to receive this
                // key must not get a paste card for its replacement instead. `deliver` makes
                // that call (it re-reads the flag), so every door sees the same answer.
                Gate::Open => match deliver(ctx, project, agent, name, &identity, &value, None, budget)? {
                    Delivery::Injected { path, unverified } => {
                        outcomes.push(Outcome::Injected { name: name.clone(), identity, written_to: path.display().to_string(), generated: false, unverified });
                    }
                    Delivery::Rejected { reason } => outcomes.push(replacement(ctx, project, agent, name, &identity, opts, &reason)?),
                },
                Gate::NeedsApproval { reason } => {
                    if reason == GateReason::OutsideTrustRoots {
                        outside = true;
                    }
                    // Carry the identity into the approval so the approver injects the key
                    // that was actually requested, not the binding/default.
                    gated.push(format!("{name}@{identity}"));
                    // placeholder; task id filled below
                    outcomes.push(Outcome::Pending { name: name.clone(), identity: identity.clone(), task_id: String::new(), title: String::new(), url: None });
                }
            }
            continue;
        }

        // Miss. Generate locally if the registry says so.
        if let Some(spec) = provider.and_then(|p| p.generate.as_deref()) {
            if let Some(v) = generate(spec) {
                let p = tasks::store_and_inject(ctx, name, &identity, &v, provider.map(|p| p.provider.clone()), None, false, project, agent, None, tasks::Verified::Unknown)?;
                outcomes.push(Outcome::Injected { name: name.clone(), identity, written_to: p.map(|p| p.display().to_string()).unwrap_or_default(), generated: true, unverified: false });
                continue;
            }
        }

        // Honor a recent refusal: "denied — do not ask again" must actually mean that.
        if !opts.force {
            let since = (chrono::Utc::now() - chrono::Duration::hours(ctx.cfg.task_ttl_hours as i64)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            if let Some(d) = ctx.db.recent_denial(&pid, name, &identity, &since)? {
                outcomes.push(Outcome::Denied { name: name.clone(), task_id: d.id });
                continue;
            }
        }
        let t = tasks::create_secret_task(ctx, project, agent, name, &identity, &opts.req)?;
        outcomes.push(Outcome::Pending { name: name.clone(), identity: identity.clone(), task_id: t.id, title: t.title, url: t.url });
    }

    if !gated.is_empty() {
        let mut names_for_task = gated.clone();
        if outside {
            names_for_task.push("*".into());
        }
        // "Deny" on an approval card is remembered for task_ttl_hours, like a denied paste:
        // every gated entry the human already refused for this project comes back Denied
        // instead of a fresh card. Without this a program failing in a loop files a new card
        // per failure until the human clicks through.
        // Every denial still inside the TTL counts, not just the newest: each card may have
        // covered different keys.
        let mut denied_entries: Vec<(String, String)> = vec![]; // (entry, denying task id)
        if !opts.force {
            let since = (chrono::Utc::now() - chrono::Duration::hours(ctx.cfg.task_ttl_hours as i64)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            for d in ctx.db.recent_denied_approvals(&pid, &since)? {
                for g in &gated {
                    if denied_entries.iter().any(|(e, _)| e == g) {
                        continue;
                    }
                    // Only the keys that card actually named. The `*` an outside-root card
                    // carries is the project-wide GRANT offer; refusing it is not "deny every
                    // future key here" — a different key deserves its own card.
                    let name_only = tasks::split_identity(g).0.to_string();
                    let covered = d.names.iter().any(|n| n == g || n == &name_only);
                    if covered {
                        denied_entries.push((g.clone(), d.id.clone()));
                    }
                }
            }
            for o in outcomes.iter_mut() {
                if let Outcome::Pending { name, identity, .. } = o {
                    if let Some((_, tid)) = denied_entries.iter().find(|(e, _)| e == &format!("{name}@{identity}")) {
                        *o = Outcome::Denied { name: name.clone(), task_id: tid.clone() };
                    }
                }
            }
        }
        let denied_entries: Vec<String> = denied_entries.into_iter().map(|(e, _)| e).collect();
        let still_gated: Vec<String> = gated.iter().filter(|g| !denied_entries.contains(g)).cloned().collect();
        if !still_gated.is_empty() {
            let names_for_task: Vec<String> = names_for_task.into_iter().filter(|n| n == "*" || still_gated.contains(n)).collect();
            // Program-derived requests never merge with another invocation's pending approval.
            let t = tasks::create_approval_task_opts(ctx, project, agent, &names_for_task, !opts.require_approval)?;
            for o in outcomes.iter_mut() {
                if let Outcome::Pending { name, identity, task_id, title, .. } = o {
                    if task_id.is_empty() && still_gated.contains(&format!("{name}@{identity}")) {
                        *task_id = t.id.clone();
                        *title = t.title.clone();
                    }
                }
            }
        }
    }

    if opts.blocking && outcomes.iter().any(|o| o.is_pending()) {
        wait(ctx, project, &mut outcomes, opts.timeout)?;
    }
    Ok(outcomes)
}

/// Poll until every pending task resolves or the timeout elapses. Callers that already
/// filed tasks use this instead of calling `need` again, so no duplicate tasks are created.
pub fn wait(ctx: &Ctx, project: &Path, outcomes: &mut [Outcome], timeout: Duration) -> Result<()> {
    let project = &project.canonicalize().unwrap_or_else(|_| project.to_path_buf());
    let start = Instant::now();
    let mut budget = ProbeBudget::default();
    loop {
        let mut any_pending = false;
        for o in outcomes.iter_mut() {
            if let Outcome::Pending { name, identity, task_id, .. } = o {
                let Some(t) = ctx.db.get_task(task_id)? else { continue };
                match t.status {
                    TaskStatus::Pending => any_pending = true,
                    TaskStatus::Answered => {
                        // Answered means stored/approved; do not assume injected, and do not
                        // trust a same-named entry already in the file (it may belong to another
                        // identity). Always inject the identity THIS request asked for; the
                        // write is an idempotent upsert.
                        let written: PathBuf = project.join(&ctx.cfg.env_file);
                        let v = ctx.stash.get(&stash_key(name, identity))?
                            .ok_or_else(|| anyhow::anyhow!("task {} is answered but {name}@{identity} is not in the stash", t.id))?;
                        match deliver(ctx, project, &t.agent, name, identity, &v, Some("after-answer"), &mut budget)
                            .map_err(|e| anyhow::anyhow!("{name} is stored but could not be delivered to {}: {e:#}", written.display()))?
                        {
                            Delivery::Injected { unverified, .. } => {
                                *o = Outcome::Injected { name: name.clone(), identity: identity.clone(), written_to: written.display().to_string(), generated: false, unverified };
                            }
                            // Approved, then found dead at delivery: file the replacement so
                            // the human sees it now; the caller keeps waiting on the new card.
                            Delivery::Rejected { reason } => {
                                let why = format!("Replace {name}: {reason}. The new value is written to {}.", written.display());
                                let req = SecretRequest { why: Some(why), ..Default::default() };
                                let nt = tasks::create_replacement_task(ctx, project, &t.agent, name, identity, &req)?;
                                *o = Outcome::Pending { name: name.clone(), identity: identity.clone(), task_id: nt.id, title: nt.title, url: nt.url };
                                any_pending = true;
                            }
                        }
                    }
                    TaskStatus::Denied => *o = Outcome::Denied { name: name.clone(), task_id: task_id.clone() },
                    TaskStatus::Expired => *o = Outcome::Expired { name: name.clone(), task_id: task_id.clone() },
                }
            }
        }
        if !any_pending || start.elapsed() > timeout {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Wall-clock a single `need`/`wait`/approval may spend on verify-on-use probes. Past it,
/// remaining keys are delivered unverified: an offline agent asking for five keys must not
/// wait five timeouts.
#[derive(Default)]
pub struct ProbeBudget {
    spent: Duration,
}
impl ProbeBudget {
    pub const MAX: Duration = Duration::from_secs(6);
    /// A budget with nothing left (tests; callers that must not wait on the network).
    pub fn exhausted() -> Self { Self { spent: Self::MAX } }
}

/// Lease taken before a probe goes on the wire, and the backoff after "no verdict".
const PROBE_LEASE: chrono::Duration = chrono::Duration::minutes(10);
const PROBE_BACKOFF_RATE_LIMITED: chrono::Duration = chrono::Duration::minutes(60);
/// After an Ok, no probe for at least this long whatever `verify_every` says: `always`
/// means "every call, at most once a minute", so a `need` loop cannot become a request
/// loop against the user's real quota.
const PROBE_FLOOR: chrono::Duration = chrono::Duration::seconds(60);

/// The routine window as a chrono duration (`Always` → the floor).
fn window(cfg: &crate::config::Config) -> chrono::Duration {
    use crate::config::VerifyEvery::*;
    match cfg.verify_every {
        Always | Never => PROBE_FLOOR,
        Every(d) => chrono::Duration::from_std(d).unwrap_or_else(|_| chrono::Duration::days(1)).max(PROBE_FLOOR),
    }
}

/// Agent names come from the caller (`--agent`, `TOKENSTASH_AGENT`, MCP `clientInfo.name`)
/// and end up in audit rows and on cards ("found at use by <agent>"). Short and printable,
/// so a caller cannot write the card's body.
pub fn clean_agent(raw: &str) -> String {
    let clean: String = raw.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-')).take(48).collect();
    let clean = clean.trim().to_string();
    if clean.is_empty() { "agent".into() } else { clean }
}

fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub enum Delivery {
    Injected { path: PathBuf, unverified: bool },
    /// The provider rejected the stored value just now. It is marked stale; the caller files
    /// the replacement card. Nothing was written.
    Rejected { reason: String },
}

enum AtUse {
    NotDue,
    Verified,
    Unverified,
    Rejected(String),
    /// The stash changed under the probe: deliver what is stored now, unverified.
    Changed(SecretString),
}

/// Hand a stash value to a project. Every path that writes a stored key into an env file
/// after authorization goes through here — the plain hit, the after-approval inject, the
/// after-answer inject — so neither verify-on-use nor the stale flag can be bypassed by
/// taking a different door.
#[allow(clippy::too_many_arguments)]
pub fn deliver(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, value: &SecretString, note: Option<&str>, budget: &mut ProbeBudget) -> Result<Delivery> {
    let pid = project.to_string_lossy().to_string();
    // Re-read: the flag may have been set after the caller looked (a report from another
    // project while an approval card was pending, a probe in another process).
    if let Some(m) = ctx.db.get_secret(name, identity)? {
        if m.stale {
            return Ok(Delivery::Rejected { reason: m.stale_reason.unwrap_or_else(|| "the stored key was marked stale".into()) });
        }
    }
    let mut current = value.clone();
    let unverified = match verify_at_use(ctx, project, agent, name, identity, value, budget)? {
        AtUse::Rejected(reason) => return Ok(Delivery::Rejected { reason }),
        AtUse::Changed(v) => { current = v; true }
        AtUse::Unverified => true,
        AtUse::NotDue | AtUse::Verified => false,
    };
    let path = crate::envfile::write(project, &ctx.cfg.env_file, name, &current)?;
    ctx.db.touch_secret(name, identity)?;
    ctx.db.audit(Some(&pid), Some(agent), "inject", Some(name), Some(identity), note)?;
    Ok(Delivery::Injected { path, unverified })
}

/// Re-check a stored key with its provider before delivering it, when due. See §14.7.
///
/// Due = the registry allows this probe unattended (`check.at_use`), the human has not
/// turned it off for this key, `verify_every` says so, no backoff/lease is in force.
/// The probe transmits the key, so this runs only after the trust gate has opened.
fn verify_at_use(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, value: &SecretString, budget: &mut ProbeBudget) -> Result<AtUse> {
    use crate::config::VerifyEvery;
    if matches!(ctx.probe, tasks::Probe::Off) || ctx.cfg.verify_every == VerifyEvery::Never {
        return Ok(AtUse::NotDue);
    }
    let Some(check) = registry::lookup(name).and_then(|p| p.check.as_ref()).filter(|c| c.at_use) else {
        return Ok(AtUse::NotDue);
    };
    let Some(meta) = ctx.db.get_secret(name, identity)? else { return Ok(AtUse::NotDue) };
    if meta.verify_off || meta.stale {
        return Ok(AtUse::NotDue);
    }
    let now = chrono::Utc::now();
    if let VerifyEvery::Every(d) = ctx.cfg.verify_every {
        // A timestamp we cannot parse, or one from the future (clock moved back), counts as
        // "never verified": probing is the safe answer to bad data.
        let fresh = meta.last_verified.as_deref().and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok()).map(|t| {
            let t = t.with_timezone(&chrono::Utc);
            t <= now && now - t < chrono::Duration::from_std(d).unwrap_or_else(|_| chrono::Duration::days(1))
        }).unwrap_or(false);
        if fresh {
            return Ok(AtUse::NotDue);
        }
    }
    // Out of time for this call: deliver unverified without taking a lease, so the next
    // call (or another process) still gets to probe.
    if budget.spent >= ProbeBudget::MAX {
        return Ok(AtUse::Unverified);
    }
    // Backoff, floor and lease live in one column (never the routine window, which is
    // derived from `last_verified` so a config change applies at once): a future
    // `next_probe` means "not now", whoever set it. `claim_probe` is a conditional UPDATE,
    // so two processes racing to the same due key produce one request, not two. A key
    // inside a backoff is delivered, but the caller is told it was not checked.
    if !ctx.db.claim_probe(name, identity, &rfc3339(now + PROBE_LEASE))? {
        return Ok(AtUse::Unverified);
    }
    let started = Instant::now();
    let verdict = ctx.probe.run(check, value, crate::validate::TIMEOUT_AT_USE);
    budget.spent += started.elapsed();
    let Some(verdict) = verdict else { return Ok(AtUse::NotDue) };
    // Another process may have replaced the value while the probe was in flight (the human
    // answered a card): a verdict about the old value says nothing about the new one, and
    // the old one must not be written over the new.
    match ctx.stash.get(&stash_key(name, identity))? {
        Some(v) if v.expose_secret() == value.expose_secret() => {}
        Some(v) => return Ok(AtUse::Changed(v)),
        None => return Ok(AtUse::Unverified),
    }
    let pid = project.to_string_lossy().to_string();
    match verdict {
        Liveness::Ok => {
            ctx.db.set_verified(name, identity)?;
            ctx.db.set_next_probe(name, identity, &rfc3339(chrono::Utc::now() + PROBE_FLOOR))?;
            Ok(AtUse::Verified)
        }
        Liveness::Rejected(code) => {
            let provider = registry::lookup(name).map(|p| p.provider.as_str()).unwrap_or("the provider");
            let reason = format!("rejected by {provider} (HTTP {code}) on {}, found at use by {agent} in {}", crate::now(), crate::project::short(project));
            ctx.db.mark_stale(name, identity, true, Some(&reason), Some(crate::db::STALE_PROBE))?;
            ctx.db.audit(Some(&pid), Some(agent), "probe.rejected", Some(name), Some(identity), Some(&format!("HTTP {code}")))?;
            Ok(AtUse::Rejected(reason))
        }
        Liveness::Unknown(_) => {
            // 403 is a verdict ("live, not permitted here") that will not change: wait a
            // whole window, not a backoff, or a restricted key is probed every ten minutes.
            let wait = if verdict.is_rate_limited() { PROBE_BACKOFF_RATE_LIMITED } else if verdict.is_forbidden() { window(ctx.cfg) } else { PROBE_LEASE };
            ctx.db.set_next_probe(name, identity, &rfc3339(chrono::Utc::now() + wait))?;
            Ok(AtUse::Unverified)
        }
    }
}

/// The stash holds a value the project may have, but it is stale: regenerate a generated
/// secret, honour a recent "do not ask again", else file the replacement card.
fn replacement(ctx: &Ctx, project: &Path, agent: &str, name: &str, identity: &str, opts: &NeedOpts, reason: &str) -> Result<Outcome> {
    let pid = project.to_string_lossy().to_string();
    let provider = registry::lookup(name);
    // Generated secrets are never pasted: regenerate.
    if let Some(spec) = provider.and_then(|p| p.generate.as_deref()) {
        if let Some(v) = generate(spec) {
            let p = tasks::store_and_inject(ctx, name, identity, &v, provider.map(|p| p.provider.clone()), None, false, project, agent, None, tasks::Verified::Unknown)?;
            return Ok(Outcome::Injected { name: name.into(), identity: identity.into(), written_to: p.map(|p| p.display().to_string()).unwrap_or_default(), generated: true, unverified: false });
        }
    }
    if !opts.force {
        let since = (chrono::Utc::now() - chrono::Duration::hours(ctx.cfg.task_ttl_hours as i64)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        if let Some(d) = ctx.db.recent_denial(&pid, name, identity, &since)? {
            return Ok(Outcome::Denied { name: name.into(), task_id: d.id });
        }
    }
    // The value stays in the stash (a live re-paste of the same value self-heals a false
    // positive); the card says why, so the human can judge the report.
    let why = format!("Replace {name}: {reason}. The new value is written to {}.", project.join(&ctx.cfg.env_file).display());
    let req = SecretRequest { why: Some(why), ..opts.req.clone() };
    let t = tasks::create_replacement_task(ctx, project, agent, name, identity, &req)?;
    Ok(Outcome::Pending { name: name.into(), identity: identity.into(), task_id: t.id, title: t.title, url: t.url })
}
