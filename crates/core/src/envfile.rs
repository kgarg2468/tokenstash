//! Write secrets into a project env file and make sure it can't be committed.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::path::{Path, PathBuf};

/// Upsert `NAME=value` into `<project>/<env_file>`. Preserves other lines. 0600.
pub fn write(project: &Path, env_file: &str, name: &str, value: &SecretString) -> Result<PathBuf> {
    let path = project.join(env_file);
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
    ensure_gitignore(project, env_file)?;
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
