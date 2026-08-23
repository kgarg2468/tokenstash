//! Write secrets into a project env file and make sure it can't be committed.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Upsert `NAME=value` into `<project>/<env_file>`. Preserves other lines. 0600.
///
/// The file is made uncommittable BEFORE the value touches disk (gitignore entry +
/// untracking a previously committed file), so a failure here can never leave a secret
/// in a commit-eligible file.
pub fn write(project: &Path, env_file: &str, name: &str, value: &SecretString) -> Result<PathBuf> {
    let path = project.join(env_file);
    let real = resolve_real(&path)?;
    // A symlink anywhere on this path (final component OR an ancestor) would route the
    // secret outside the protected location (a tracked file, another user's config…):
    // refuse rather than follow it.
    if path.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) || real != path {
        anyhow::bail!(
            "{} is or crosses a symlink — refusing to write a secret through it. Remove the link and re-run.",
            path.display()
        );
    }
    enforce_uncommittable(project, env_file)?;
    let existing = if path.exists() { fs::read_to_string(&path)? } else { String::new() };
    let mut out = String::with_capacity(existing.len() + 64);
    let mut replaced = false;
    let prefix = format!("{name}=");
    let export_prefix = format!("export {name}=");
    for line in existing.lines() {
        if line.starts_with(&prefix) || line.starts_with(&export_prefix) {
            if !replaced {
                out.push_str(&prefix);
                out.push_str(&quote(value.expose_secret()));
                out.push('\n');
                replaced = true;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !replaced {
        out.push_str(&prefix);
        out.push_str(&quote(value.expose_secret()));
        out.push('\n');
    }
    fs::write(&path, out).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

/// Does the env file already contain NAME= ?
pub fn has(project: &Path, env_file: &str, name: &str) -> bool {
    let path = project.join(env_file);
    let Ok(s) = fs::read_to_string(path) else { return false };
    let p = format!("{name}=");
    s.lines().any(|l| l.starts_with(&p) || l.starts_with(&format!("export {p}")))
}

fn quote(v: &str) -> String {
    let needs = v.chars().any(|c| c.is_whitespace() || c == '#' || c == '"' || c == '\'' || c == '$');
    if needs {
        format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        v.to_string()
    }
}

/// Walk up to find a git repo root.
pub fn git_root(start: &Path) -> Option<PathBuf> {
    let mut p = start.to_path_buf();
    loop {
        if p.join(".git").exists() {
            return Some(p);
        }
        if !p.pop() {
            return None;
        }
    }
}

/// If inside a git repo, make sure `.gitignore` at the root ignores the env file.
pub fn ensure_gitignore(project: &Path, env_file: &str) -> Result<bool> {
    let Some(root) = git_root(project) else { return Ok(false) };
    let gi = root.join(".gitignore");
    let existing = if gi.exists() { fs::read_to_string(&gi)? } else { String::new() };
    let covered = existing.lines().map(str::trim).any(|l| {
        l == env_file
            || l == format!("/{env_file}")
            || l == "*.local"
            || l == ".env*"
            || l == ".env.*"
            || (l == "*.env" && env_file.ends_with(".env"))
    });
    if covered {
        return Ok(false);
    }
    let mut s = existing;
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s.push_str("# added by tokenstash — never commit injected secrets\n");
    s.push_str(env_file);
    s.push('\n');
    fs::write(&gi, s)?;
    Ok(true)
}

/// Guarantee the env file cannot be committed: cover it in `.gitignore` and, if it is
/// already tracked (ignore rules don't apply to indexed files), remove it from the index.
fn enforce_uncommittable(project: &Path, env_file: &str) -> Result<()> {
    ensure_gitignore(project, env_file)?;
    untrack(project, env_file)
}

/// Fully resolve a path's existing ancestors so writes can't slip through symlinked
/// parent directories. Errors only if the file itself exists but can't be resolved.
fn resolve_real(path: &Path) -> Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| anyhow::anyhow!("bad env path {}", path.display()))?;
    match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Ok(PathBuf::from(file_name)),
        Some(parent) => Ok(parent.canonicalize().unwrap_or_else(|_| parent.to_path_buf()).join(file_name)),
        None => Ok(PathBuf::from(file_name)),
    }
}

/// `git rm --cached` a tracked env file so a future `git add -A` can't pick up secrets.
/// Missing git binary → nothing to do. Failure to untrack → hard error, value not written.
fn untrack(project: &Path, env_file: &str) -> Result<()> {
    let Some(root) = git_root(project) else { return Ok(()) };
    let rel = project
        .strip_prefix(&root)
        .unwrap_or(Path::new(""))
        .join(env_file);
    let tracked = Command::new("git")
        .args(["ls-files", "--", &*rel.to_string_lossy()])
        .current_dir(&root)
        .output();
    let Ok(out) = tracked else { return Ok(()) };
    if !out.status.success() || out.stdout.is_empty() {
        return Ok(());
    }
    let removed = Command::new("git")
        .args(["rm", "--cached", "--quiet", "--", &*rel.to_string_lossy()])
        .current_dir(&root)
        .status();
    match removed {
        Ok(s) if s.success() => eprintln!("tokenstash: {env_file} was tracked by git — untracked it so injected secrets can't be committed"),
        _ => anyhow::bail!("could not untrack the already-committed {env_file}; refusing to write a secret into a commit-eligible file. Run: git rm --cached {env_file}"),
    }
    Ok(())
}
