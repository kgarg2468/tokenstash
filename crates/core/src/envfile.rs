//! Write secrets into a project env file and make sure it can't be committed.
//!
//! Grammar we emit (the common subset every dotenv parser agrees on):
//! - `NAME=value` unquoted when the value is `[A-Za-z0-9_./:@+=-]` only.
//! - Otherwise `NAME="value"` with `\` and `"` backslash-escaped. `$` is written as-is:
//!   dotenv expansion is opt-in in most loaders (dotenv-expand, Next.js) and escaping it
//!   as `\$` is read literally by others (python-dotenv). Secrets containing `$` are rare;
//!   `run --` injects into the process env and sidesteps the file entirely.
//! - We never emit single quotes, backticks, or `export`.

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
    write_private(&path, &out).with_context(|| format!("writing {}", path.display()))?;
    ensure_gitignore(project, env_file)?;
    Ok(path)
}

/// Create-or-truncate with 0600 from the first byte; tighten an existing file; fail loudly
/// if permissions cannot be applied rather than leaving a readable secret behind.
fn write_private(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(contents.as_bytes())?;
    Ok(())
}

/// Does the env file already contain NAME= ?
pub fn has(project: &Path, env_file: &str, name: &str) -> bool {
    let path = project.join(env_file);
    let Ok(s) = fs::read_to_string(path) else { return false };
    let p = format!("{name}=");
    s.lines().any(|l| l.starts_with(&p) || l.starts_with(&format!("export {p}")))
}

fn quote(v: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "_./:@+=-".contains(c);
    if !v.is_empty() && v.chars().all(safe) {
        v.to_string()
    } else {
        format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// Parse a line we (or a human) wrote, for round-trip tests and the `run` shim.
pub fn parse_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let line = line.strip_prefix("export ").unwrap_or(line);
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (k, v) = line.split_once('=')?;
    let v = v.trim();
    let val = if let Some(inner) = v.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some(o) => out.push(o),
                    None => out.push('\\'),
                }
            } else {
                out.push(c);
            }
        }
        out
    } else if let Some(inner) = v.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
        inner.to_string()
    } else {
        v.split('#').next().unwrap_or("").trim().to_string()
    };
    Some((k.trim().to_string(), val))
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
