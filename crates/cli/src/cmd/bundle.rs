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
    let out = if out.is_absolute() { out } else { std::env::current_dir()?.join(out) };
    let out = refuse_bad_destination(&out, &app.cfg.env_file)?;
    let secrets = app.db.list_secrets()?;
    if secrets.is_empty() {
        println!("nothing indexed in this home; nothing to export");
        return Ok(0);
    }
    let mut entries = Vec::with_capacity(secrets.len());
    let mut missing = 0usize;
    for m in &secrets {
        match app.stash.get(&stash_key(&m.name, &m.identity))? {
            Some(v) => entries.push(Entry { name: m.name.clone(), identity: m.identity.clone(), value: v.expose_secret().to_string(), provider: m.provider.clone(), sensitive: m.sensitive, source_url: m.source_url.clone(), created: m.created.clone(), last_used: m.last_used.clone(), stale: m.stale, stale_reason: m.stale_reason.clone() }),
            None => missing += 1,
        }
    }
    let bindings = app.db.list_bindings()?.into_iter().map(|(project, name, identity)| Binding { project, name, identity }).collect();
    let payload = Payload_ { created: tokenstash_core::now(), tool_version: env!("CARGO_PKG_VERSION").into(), entries, bindings };

    println!("Exporting {} of {} indexed secrets{} to {}", payload.entries.len(), secrets.len(), if missing > 0 { format!(" ({missing} indexed but not in the stash, skipped)") } else { String::new() }, out.display());
    println!("Choose a passphrase (12+ characters), or press Enter to generate one.");
    let pw = rpassword::prompt_password("passphrase: ")?;
    let pw = if pw.is_empty() {
        use std::io::IsTerminal;
        if !std::io::stdout().is_terminal() {
            bail!("stdout is not a terminal, so a generated passphrase would land in a file or a pipe; choose one instead");
        }
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

/// A bundle holds every value: never into a device/pipe, a git-tracked path, a checkout
/// owned by someone else (owned_git_root's hard error propagates), or a project's env-file
/// name (a bundle is not an env file, and that name is what agents read).
fn refuse_bad_destination(p: &Path, env_file: &str) -> Result<PathBuf> {
    let Some(file_name) = p.file_name() else { bail!("{} is not a file path", p.display()) };
    if file_name.to_string_lossy() == env_file {
        bail!("refusing to write the bundle as {}: that is the env-file name agents read", p.display());
    }
    // Resolve the parent first: the checks below and the rename that follows must look at
    // the same directory, and a symlinked parent would otherwise let the rename land in a
    // checkout the lexical check never saw.
    let parent = p.parent().filter(|d| !d.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let parent = parent.canonicalize().with_context(|| format!("{} does not exist", parent.display()))?;
    let resolved = parent.join(file_name);
    if resolved.starts_with("/dev") || resolved.starts_with("/proc") || resolved.starts_with("/sys") { bail!("refusing to write the bundle to {}", resolved.display()); }
    if let Some(root) = tokenstash_core::envfile::owned_git_root(&parent)? {
        if tokenstash_core::envfile::is_git_tracked(&root, &resolved) {
            bail!("{} is tracked by git; refusing to write a bundle there", resolved.display());
        }
        eprintln!("note: {} is inside a git repo — make sure the bundle is never committed", resolved.display());
    }
    Ok(resolved)
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
    /// Also apply the bundle's project bindings (which identity a project uses). Off by
    /// default: a binding changes which value a project receives, so it is listed, not applied.
    #[arg(long)]
    pub apply_bindings: bool,
}

pub fn import(a: ImportArgs) -> Result<i32> {
    require_human("import")?;
    let app = App::open()?;
    let size = std::fs::metadata(&a.bundle).with_context(|| format!("reading {}", a.bundle.display()))?.len();
    if size as usize > bundle::MAX_BUNDLE_BYTES {
        bail!("{} is {size} bytes; a bundle is never that large", a.bundle.display());
    }
    let bytes = std::fs::read(&a.bundle).with_context(|| format!("reading {}", a.bundle.display()))?;
    let pw = SecretString::from(rpassword::prompt_password("passphrase: ")?);
    let payload = bundle::open(&bytes, &pw)?;
    println!("bundle from {} ({} entries, {} bindings)", payload.created, payload.entries.len(), payload.bindings.len());

    // 1. validate everything before touching anything: one bad entry refuses the whole file
    if payload.entries.len() > bundle::MAX_ENTRIES {
        bail!("bundle has {} entries; refusing more than {}", payload.entries.len(), bundle::MAX_ENTRIES);
    }
    for e in &payload.entries {
        bundle::validate_entry(e).context("refusing the whole import")?;
        // What a paste would have rejected, an import rejects too.
        if let Some(pat) = tokenstash_core::registry::lookup(&e.name).and_then(|p| p.pattern.as_ref()) {
            if !tokenstash_core::validate::matches_pattern(pat, &SecretString::from(e.value.clone()))? {
                bail!("entry {}@{} does not match the expected shape for {}; refusing the whole import", e.name, e.identity, e.name);
            }
        }
    }
    // 2. resolve conflicts, one question per name, before applying
    #[derive(PartialEq)] enum Plan { Add, Skip, Replace, CarryRotation }
    let mut plan: Vec<(Plan, &Entry)> = vec![];
    for e in &payload.entries {
        let existing = app.stash.get(&stash_key(&e.name, &e.identity))?;
        let p = match existing {
            None => Plan::Add,
            Some(v) if v.expose_secret() == e.value => {
                // Same value: nothing to store, but a rotation the user asked for on the
                // other machine must not be lost here. Decided now, written in the apply
                // step with everything else — planning changes nothing.
                if e.stale && e.stale_reason.as_deref().unwrap_or("").starts_with(tokenstash_core::db::Db::ROTATE_REASON)
                    && !app.db.get_secret(&e.name, &e.identity)?.map(|m| m.stale).unwrap_or(false)
                { Plan::CarryRotation } else { Plan::Skip }
            }
            Some(_) => {
                if a.keep_existing { Plan::Skip } else if a.replace { Plan::Replace } else {
                    let local = app.db.get_secret(&e.name, &e.identity)?;
                    print!("{}@{} differs from what this machine has (here: stored {}{}; bundle: stored {}{}) — replace it? [y/N] ",
                        e.name, e.identity,
                        local.as_ref().map(|m| m.created.clone()).unwrap_or_default(), if local.as_ref().map(|m| m.stale).unwrap_or(false) { ", STALE" } else { "" },
                        e.created, if e.stale { ", stale" } else { "" });
                    use std::io::Write;
                    std::io::stdout().flush()?;
                    let mut ans = String::new();
                    std::io::stdin().read_line(&mut ans)?;
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
            Plan::CarryRotation => {
                app.db.mark_stale(&e.name, &e.identity, true, e.stale_reason.as_deref())?;
                println!("  {}@{}: same value, marked for rotation as on the exporting machine", e.name, e.identity);
                skipped += 1;
                continue;
            }
            Plan::Add => added += 1,
            Plan::Replace => replaced += 1,
        }
        app.stash.set(&stash_key(&e.name, &e.identity), &SecretString::from(e.value.clone()))?;
        let provider = tokenstash_core::registry::lookup(&e.name);
        let value = SecretString::from(e.value.clone());
        // Sensitivity is re-derived here exactly as a paste derives it; the bundle cannot
        // downgrade a registry-sensitive name or a live-mode value.
        let by_pattern = match provider.and_then(|p| p.sensitive_pattern.as_ref()) {
            Some(sp) => tokenstash_core::validate::matches_pattern(sp, &value)?,
            None => false,
        };
        app.db.upsert_secret(&tokenstash_core::db::SecretMeta {
            name: e.name.clone(), identity: e.identity.clone(),
            provider: e.provider.clone().or_else(|| provider.map(|p| p.provider.clone())),
            sensitive: e.sensitive || provider.map(|p| p.sensitive).unwrap_or(false) || by_pattern,
            source_url: e.source_url.clone().or_else(|| provider.map(|p| p.url.clone())),
            created: e.created.clone(), last_used: e.last_used.clone(), stale: e.stale,
            last_verified: None,
            stale_reason: if e.stale { e.stale_reason.clone().or_else(|| Some("stale on the exporting machine".into())) } else { None },
        })?;
        app.db.audit(None, None, "import", Some(&e.name), Some(&e.identity), Some(&format!("from {}", a.bundle.display())))?;
    }
    let mut bound = 0;
    for b in &payload.bindings {
        let dir = Path::new(&b.project);
        if !dir.is_absolute() || !dir.is_dir() { continue; }
        if a.apply_bindings {
            app.db.set_binding(&b.project, &b.name, &b.identity)?;
            bound += 1;
            println!("  binding applied: {} → {}@{}", tokenstash_core::project::short(dir), b.name, b.identity);
        } else {
            println!("  binding NOT applied (use --apply-bindings): {} → {}@{}", tokenstash_core::project::short(dir), b.name, b.identity);
        }
    }
    println!("✓ {added} added, {replaced} replaced, {skipped} unchanged; {bound} of {} bindings applied", payload.bindings.len());
    // Keys that arrived stale are already a miss; verifying them gains nothing, and a probe
    // saying "still live" must not un-stale a rotation the user asked for on the old machine.
    // Also re-probe a key that was skipped as identical but is stale HERE and fresh in the
    // bundle: the other machine may have a working copy of the same value.
    let mut pairs: Vec<(String, String)> = plan.iter().filter(|(p, e)| *p != Plan::Skip && !e.stale).map(|(_, e)| (e.name.clone(), e.identity.clone())).collect();
    for (p, e) in &plan {
        if *p == Plan::Skip && !e.stale && app.db.get_secret(&e.name, &e.identity)?.map(|m| m.stale && !m.stale_reason.as_deref().unwrap_or("").starts_with(tokenstash_core::db::Db::ROTATE_REASON)).unwrap_or(false) {
            pairs.push((e.name.clone(), e.identity.clone()));
        }
    }
    drop(plan);
    drop(payload);

    // 4. verify after everything is stored, never before: a network failure must not leave a
    //    half-imported stash. Same sweep as `tokenstash check`.
    if !a.no_verify && !pairs.is_empty() {
        println!("verifying imported keys against their providers (--no-verify to skip)…");
        crate::cmd::admin::sweep_pairs(&app, &pairs, true)?;
    }
    println!("delete {} when you are done with it", a.bundle.display());
    Ok(0)
}
