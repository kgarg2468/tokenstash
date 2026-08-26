//! `need`: the one call an agent makes. Hit → inject silently (unless gated). Miss → file a task.

use crate::db::TaskStatus;
use crate::stash::stash_key;
use crate::tasks::{self, Ctx, SecretRequest};
use crate::trust::{self, Gate, GateReason};
use crate::registry;
use anyhow::{Context, Result};
use secrecy::SecretString;
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
    Injected { name: String, identity: String, written_to: String, generated: bool },
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
                };
                ctx.db.upsert_secret(&m)?;
                ctx.db.audit(Some(&pid), Some(agent), "adopt", Some(name), Some(&identity), Some("found in the stash but not in this home's index"))?;
                meta = Some(m);
            }
            // A stale key is a miss: the value is still in the stash (a live re-paste of the
            // same value self-heals a false positive), but nothing injects it. The card says
            // why, so the human can judge the report before pasting a replacement.
            if let Some(m) = meta.as_ref().filter(|m| m.stale) {
                if !opts.force {
                    let since = (chrono::Utc::now() - chrono::Duration::hours(ctx.cfg.task_ttl_hours as i64)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                    if let Some(d) = ctx.db.recent_denial(&pid, name, &identity, &since)? {
                        outcomes.push(Outcome::Denied { name: name.clone(), task_id: d.id });
                        continue;
                    }
                }
                let why = format!("Replace {name}: {}", m.stale_reason.clone().unwrap_or_else(|| "the stored key was marked stale".into()));
                let req = SecretRequest { why: Some(why), ..opts.req.clone() };
                let t = tasks::create_secret_task(ctx, project, agent, name, &identity, &req)?;
                outcomes.push(Outcome::Pending { name: name.clone(), identity: identity.clone(), task_id: t.id, title: t.title, url: t.url });
                continue;
            }
            let sensitive = meta.as_ref().map(|m| m.sensitive).unwrap_or_else(|| provider.map(|p| p.sensitive).unwrap_or(false));
            let gate = if opts.require_approval {
                Gate::NeedsApproval { reason: GateReason::Sensitive }
            } else {
                trust::gate(ctx.db, ctx.cfg, project, name, sensitive)?
            };
            match gate {
                Gate::Open => {
                    let p = crate::envfile::write(project, &ctx.cfg.env_file, name, &value)?;
                    ctx.db.touch_secret(name, &identity)?;
                    ctx.db.audit(Some(&pid), Some(agent), "inject", Some(name), Some(&identity), None)?;
                    outcomes.push(Outcome::Injected { name: name.clone(), identity, written_to: p.display().to_string(), generated: false });
                }
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
                let p = tasks::store_and_inject(ctx, name, &identity, &v, provider.map(|p| p.provider.clone()), None, false, project, agent, None, false)?;
                outcomes.push(Outcome::Injected { name: name.clone(), identity, written_to: p.map(|p| p.display().to_string()).unwrap_or_default(), generated: true });
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
                        crate::envfile::write(project, &ctx.cfg.env_file, name, &v)
                            .map_err(|e| anyhow::anyhow!("{name} is stored but could not be written to {}: {e:#}", written.display()))?;
                        ctx.db.touch_secret(name, identity)?;
                        ctx.db.audit(Some(&project.to_string_lossy()), None, "inject", Some(name), Some(identity), Some("after-answer"))?;
                        *o = Outcome::Injected { name: name.clone(), identity: identity.clone(), written_to: written.display().to_string(), generated: false };
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
