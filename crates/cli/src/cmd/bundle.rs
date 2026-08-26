//! `export` / `import`: move a stash between machines as one passphrase-encrypted file.
//! Human-only, interactive: the passphrase is prompted (never a flag, never an env var — both
//! land in `ps`, shell history, crash reports), and the export is confirmed twice so a typo
//! cannot brick the only copy.

use crate::util::App;
use anyhow::{bail, Context, Result};
use clap::Args;
use secrecy::{ExposeSecret, SecretString};
use std::path::{Path, PathBuf};
use tokenstash_core::bundle::{self, Binding, Entry, Payload_};
use tokenstash_core::stash::stash_key;

fn require_human(what: &str) -> Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || tokenstash_core::project::detect_agent() != "unknown" {
        bail!("`tokenstash {what}` is for a person at a terminal, not an agent: it handles every value in the stash. Run it yourself.");
    }
    Ok(())
}

#[derive(Args)]
pub struct ExportArgs {
    /// Where to write the bundle (default: ./tokenstash.bundle).
    #[arg(short, long)]
    pub out: Option<PathBuf>,
}

pub fn export(a: ExportArgs) -> Result<i32> {
    require_human("export")?;
    let app = App::open()?;
    let out = a.out.unwrap_or_else(|| PathBuf::from("tokenstash.bundle"));
    refuse_bad_destination(&out)?;
    let secrets = app.db.list_secrets()?;
    if secrets.is_empty() {
        println!("nothing indexed in this home; nothing to export");
        return Ok(0);
    }
    let mut entries = Vec::with_capacity(secrets.len());
    let mut missing = 0usize;
    for m in &secrets {
        match app.stash.get(&stash_key(&m.name, &m.identity))? {
            Some(v) => entries.push(Entry { name: m.name.clone(), identity: m.identity.clone(), value: v.expose_secret().to_string(), provider: m.provider.clone(), sensitive: m.sensitive, source_url: m.source_url.clone(), created: m.created.clone(), last_used: m.last_used.clone(), stale: m.stale }),
            None => missing += 1,
        }
    }
    let bindings = app.db.list_bindings()?.into_iter().map(|(project, name, identity)| Binding { project, name, identity }).collect();
    let payload = Payload_ { created: tokenstash_core::now(), tool_version: env!("CARGO_PKG_VERSION").into(), entries, bindings };

    println!("Exporting {} of {} indexed secrets{} to {}", payload.entries.len(), secrets.len(), if missing > 0 { format!(" ({missing} indexed but not in the stash, skipped)") } else { String::new() }, out.display());
    println!("Choose a passphrase (12+ characters), or press Enter to generate one.");
    let pw = rpassword::prompt_password("passphrase: ")?;
    let pw = if pw.is_empty() {
        let g = bundle::generate_passphrase();
        println!("\nGenerated passphrase — write it down now, it is shown once:\n\n    {}\n", g.expose_secret());
        g
    } else {
        let again = rpassword::prompt_password("again: ")?;
        if again != pw { bail!("passphrases do not match; nothing written"); }
        SecretString::from(pw)
    };
    let bytes = bundle::seal(&payload, &pw)?;
    tokenstash_core::fsutil::write_atomic_private_bytes(&out, &bytes).with_context(|| format!("writing {}", out.display()))?;
    app.db.audit(None, None, "export", None, None, Some(&format!("{} entries to {}", payload.entries.len(), out.display())))?;
    println!("✓ wrote {} ({} bytes, 0600). Move it with your own channel; delete it when the import is done.", out.display(), bytes.len());
    Ok(0)
}

/// A bundle holds every value: never into a git-tracked path, a project's env-file
/// location, or a device/pipe.
fn refuse_bad_destination(p: &Path) -> Result<()> {
    if p.starts_with("/dev") { bail!("refusing to write the bundle to {}", p.display()); }
    let parent = p.parent().filter(|d| !d.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    if let Some(root) = tokenstash_core::envfile::owned_git_root(&parent).ok().flatten() {
        if tokenstash_core::envfile::is_git_tracked(&root, p) {
            bail!("{} is tracked by git; refusing to write a bundle there", p.display());
        }
        eprintln!("note: {} is inside a git repo — make sure the bundle is never committed", p.display());
    }
    Ok(())
}

#[derive(Args)]
pub struct ImportArgs {
    pub bundle: PathBuf,
    /// On a conflict (same name, different value) keep what this machine has.
    #[arg(long, conflicts_with = "replace")]
    pub keep_existing: bool,
    /// On a conflict, take the bundle's value.
    #[arg(long)]
    pub replace: bool,
    /// Skip the liveness sweep after import (keys stay unverified).
    #[arg(long)]
    pub no_verify: bool,
}

pub fn import(a: ImportArgs) -> Result<i32> {
    require_human("import")?;
    let app = App::open()?;
    let bytes = std::fs::read(&a.bundle).with_context(|| format!("reading {}", a.bundle.display()))?;
    let pw = SecretString::from(rpassword::prompt_password("passphrase: ")?);
    let payload = bundle::open(&bytes, &pw)?;
    println!("bundle from {} ({} entries, {} bindings)", payload.created, payload.entries.len(), payload.bindings.len());

    // 1. validate everything before touching anything
    for e in &payload.entries {
        if e.value.chars().count() < tokenstash_core::tasks::MIN_SECRET_CHARS {
            bail!("entry {}@{} is shorter than {} characters; refusing the whole import", e.name, e.identity, tokenstash_core::tasks::MIN_SECRET_CHARS);
        }
    }
    // 2. resolve conflicts, one question per name, before applying
    #[derive(PartialEq)] enum Plan { Add, Skip, Replace }
    let mut plan: Vec<(Plan, &Entry)> = vec![];
    for e in &payload.entries {
        let existing = app.stash.get(&stash_key(&e.name, &e.identity))?;
        let p = match existing {
            None => Plan::Add,
            Some(v) if v.expose_secret() == e.value => Plan::Skip,
            Some(_) => {
                if a.keep_existing { Plan::Skip } else if a.replace { Plan::Replace } else {
                    let ans = rpassword::prompt_password(format!("{}@{} differs from what this machine has — replace it? [y/N] ", e.name, e.identity))?;
                    if ans.trim().eq_ignore_ascii_case("y") { Plan::Replace } else { Plan::Skip }
                }
            }
        };
        plan.push((p, e));
    }
    // 3. apply: stash first (the value's home), then the index. No approvals — import is not
    //    per-project consent. No env-file writes.
    let (mut added, mut replaced, mut skipped) = (0, 0, 0);
    for (p, e) in &plan {
        match p {
            Plan::Skip => { skipped += 1; continue; }
            Plan::Add => added += 1,
            Plan::Replace => replaced += 1,
        }
        app.stash.set(&stash_key(&e.name, &e.identity), &SecretString::from(e.value.clone()))?;
        let provider = tokenstash_core::registry::lookup(&e.name);
        app.db.upsert_secret(&tokenstash_core::db::SecretMeta {
            name: e.name.clone(), identity: e.identity.clone(),
            provider: e.provider.clone().or_else(|| provider.map(|p| p.provider.clone())),
            sensitive: e.sensitive || provider.map(|p| p.sensitive).unwrap_or(false),
            source_url: e.source_url.clone().or_else(|| provider.map(|p| p.url.clone())),
            created: tokenstash_core::now(), last_used: e.last_used.clone(), stale: e.stale,
            last_verified: None, stale_reason: if e.stale { Some("stale on the exporting machine".into()) } else { None },
        })?;
        app.db.audit(None, None, "import", Some(&e.name), Some(&e.identity), Some(&format!("from {}", a.bundle.display())))?;
    }
    let mut bound = 0;
    for b in &payload.bindings {
        if Path::new(&b.project).is_dir() { app.db.set_binding(&b.project, &b.name, &b.identity)?; bound += 1; }
    }
    println!("✓ {added} added, {replaced} replaced, {skipped} unchanged; {bound} of {} bindings applied (the rest name paths that do not exist here)", payload.bindings.len());
    let names: Vec<String> = plan.iter().filter(|(p, _)| *p != Plan::Skip).map(|(_, e)| e.name.clone()).collect();
    drop(plan);
    drop(payload);

    // 4. verify after everything is stored, never before: a network failure must not leave a
    //    half-imported stash. Same sweep as `tokenstash check`.
    if !a.no_verify && !names.is_empty() {
        println!("verifying imported keys against their providers (--no-verify to skip)…");
        crate::cmd::admin::sweep(&app, &names, false, true)?;
    }
    println!("delete {} when you are done with it", a.bundle.display());
    Ok(0)
}
