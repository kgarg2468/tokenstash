use crate::util::{self, App};
use anyhow::{bail, Result};
use clap::Args;
use secrecy::SecretString;
use std::io::Read;
use tokenstash_core::db::TaskKind;
use tokenstash_core::tasks::{self, AnswerResult};

#[derive(Args)]
pub struct AnswerArgs {
    /// Task id (or unique prefix). Omit to answer the oldest open task in this project.
    pub id: Option<String>,
    /// Read the value from stdin instead of a masked prompt (for scripts/tests).
    #[arg(long)]
    pub stdin: bool,
    /// Skip the provider liveness check.
    #[arg(long)]
    pub skip_check: bool,
    /// Approve (approval tasks).
    #[arg(long)]
    pub allow: bool,
    /// Deny / decline any task.
    #[arg(long)]
    pub deny: bool,
    /// Note for human tasks, or a reason when denying.
    #[arg(long)]
    pub note: Option<String>,
}

pub fn answer(a: AnswerArgs) -> Result<i32> {
    let app = App::open()?;
    app.db.expire_overdue()?;
    let task = match &a.id {
        Some(id) => app.db.find_task(id)?.ok_or_else(|| anyhow::anyhow!("no task matching '{id}'"))?,
        None => {
            let project = tokenstash_core::project::current();
            app.db.list_tasks(Some(&project.to_string_lossy()), true)?.into_iter().next().ok_or_else(|| anyhow::anyhow!("no open tasks in this project"))?
        }
    };
    let ctx = app.ctx();

    if a.deny {
        tasks::deny(&ctx, &task, a.note.as_deref())?;
        println!("✗ {} denied", task.id);
        return Ok(0);
    }

    match task.kind {
        TaskKind::Secret => {
            let name = task.name.clone().unwrap_or_default();
            println!("{}  [{}]", task.title, util::short(&task.project));
            if let Some(w) = &task.why { println!("  why: {w}"); }
            if let Some(u) = &task.url { println!("  get it at: {u}"); }
            for (i, s) in task.steps.iter().enumerate() { println!("  {}. {s}", i + 1); }
            let raw = if a.stdin {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s.trim().to_string()
            } else {
                rpassword::prompt_password(format!("Paste {name} (input hidden): "))?.trim().to_string()
            };
            if raw.is_empty() {
                bail!("empty value; nothing stored");
            }
            match tasks::answer_secret(&ctx, &task, SecretString::from(raw), a.skip_check)? {
                AnswerResult::Stored { injected_to, sensitive, liveness, rotation } => {
                    if let Some(r) = &rotation {
                        for p in &r.rewritten { println!("  also updated → {}", tokenstash_core::project::short(std::path::Path::new(p))); }
                        for (p, why) in &r.skipped { println!("  ! still holds the OLD value: {} — {why}", tokenstash_core::project::short(std::path::Path::new(p))); }
                        if !r.skipped.is_empty() { println!("  fix those before revoking the old key"); }
                    }
                    println!("✓ {name} stored in the {} stash", app.stash.backend());
                    if let Some(l) = liveness { println!("  liveness: {}", describe(&l)); }
                    if sensitive { println!("  tagged sensitive: will ask once per project"); }
                    if let Some(p) = injected_to { println!("  injected → {}", p.display()); }
                }
                _ => unreachable!(),
            }
        }
        TaskKind::Approval => {
            println!("{}", task.title);
            if let Some(w) = &task.why { println!("  {w}"); }
            println!("  keys: {}", crate::util::approval_names(&task.names).join(", "));
            let allow = if a.allow {
                true
            } else {
                let ans = rpassword::prompt_password("Allow? [y/N] (input hidden) ")?;
                matches!(ans.trim(), "y" | "Y" | "yes")
            };
            match tasks::answer_approval(&ctx, &task, allow)? {
                AnswerResult::Approved { injected, replaced } => {
                    println!("✓ approved; injected {}", if injected.is_empty() { "nothing new".into() } else { injected.join(", ") });
                    if !replaced.is_empty() { println!("  {} rejected by the provider at delivery — a Replace card is waiting", replaced.join(", ")); }
                }
                AnswerResult::Denied => println!("✗ denied"),
                _ => unreachable!(),
            }
        }
        TaskKind::Human => {
            println!("{}", task.title);
            if let Some(w) = &task.why { println!("  why: {w}"); }
            if let Some(u) = &task.url { println!("  at: {u}"); }
            for (i, s) in task.steps.iter().enumerate() { println!("  {}. {s}", i + 1); }
            let note = match (&a.note, task.expects.as_str()) {
                (Some(n), _) => Some(n.clone()),
                (None, "text") => {
                    let mut s = String::new();
                    println!("Enter your answer, then Ctrl-D:");
                    std::io::stdin().read_to_string(&mut s)?;
                    Some(s.trim().to_string())
                }
                _ => None,
            };
            tasks::answer_human(&ctx, &task, note.as_deref())?;
            println!("✓ marked done");
        }
    }
    Ok(0)
}

pub fn describe(l: &tokenstash_core::validate::Liveness) -> String {
    use tokenstash_core::validate::Liveness::*;
    match l {
        Ok => "key accepted by the provider".into(),
        Rejected(c) => format!("rejected (HTTP {c})"),
        Unknown(e) => format!("could not verify ({e}); stored anyway"),
    }
}
