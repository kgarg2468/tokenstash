//! `need`: the one call an agent makes. Hit → inject silently (unless gated). Miss → file a task.

use crate::db::TaskStatus;
use crate::stash::stash_key;
use crate::tasks::{self, Ctx, SecretRequest};
use crate::trust::{self, Gate, GateReason};
use crate::registry;
use anyhow::Result;
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
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Injected { name: String, identity: String, written_to: String, generated: bool },
    Pending { name: String, task_id: String, title: String, url: Option<String> },
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
            let meta = ctx.db.get_secret(name, &identity)?;
            let sensitive = meta.as_ref().map(|m| m.sensitive).unwrap_or_else(|| provider.map(|p| p.sensitive).unwrap_or(false));
            match trust::gate(ctx.db, ctx.cfg, project, name, sensitive)? {
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
                    gated.push(name.clone());
                    // placeholder; task id filled below
                    outcomes.push(Outcome::Pending { name: name.clone(), task_id: String::new(), title: String::new(), url: None });
                }
            }
            continue;
        }

        // Miss. Generate locally if the registry says so.
        if let Some(spec) = provider.and_then(|p| p.generate.as_deref()) {
            if let Some(v) = generate(spec) {
                let p = tasks::store_and_inject(ctx, name, &identity, &v, provider.map(|p| p.provider.clone()), None, false, project, agent)?;
                outcomes.push(Outcome::Injected { name: name.clone(), identity, written_to: p.map(|p| p.display().to_string()).unwrap_or_default(), generated: true });
                continue;
            }
        }

        // Honor a recent refusal: "denied — do not ask again" must actually mean that.
        if !opts.force {
            let since = (chrono::Utc::now() - chrono::Duration::hours(ctx.cfg.task_ttl_hours as i64)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            if let Some(d) = ctx.db.recent_denial(&pid, name, &since)? {
                outcomes.push(Outcome::Denied { name: name.clone(), task_id: d.id });
                continue;
            }
        }
        let t = tasks::create_secret_task(ctx, project, agent, name, &identity, &opts.req)?;
        outcomes.push(Outcome::Pending { name: name.clone(), task_id: t.id, title: t.title, url: t.url });
    }

    if !gated.is_empty() {
        let mut names_for_task = gated.clone();
        if outside {
            names_for_task.push("*".into());
        }
        let t = tasks::create_approval_task(ctx, project, agent, &names_for_task)?;
        for o in outcomes.iter_mut() {
            if let Outcome::Pending { name, task_id, title, .. } = o {
                if task_id.is_empty() && gated.contains(name) {
                    *task_id = t.id.clone();
                    *title = t.title.clone();
                }
            }
        }
    }

    if opts.blocking && outcomes.iter().any(|o| o.is_pending()) {
        wait(ctx, project, &mut outcomes, opts.timeout)?;
    }
    Ok(outcomes)
}

/// Poll until every pending task resolves or the timeout elapses.
fn wait(ctx: &Ctx, project: &Path, outcomes: &mut [Outcome], timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        let mut any_pending = false;
        for o in outcomes.iter_mut() {
            if let Outcome::Pending { name, task_id, .. } = o {
                let Some(t) = ctx.db.get_task(task_id)? else { continue };
                match t.status {
                    TaskStatus::Pending => any_pending = true,
                    TaskStatus::Answered => {
                        let written: PathBuf = project.join(&ctx.cfg.env_file);
                        *o = Outcome::Injected { name: name.clone(), identity: t.identity.clone(), written_to: written.display().to_string(), generated: false };
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
