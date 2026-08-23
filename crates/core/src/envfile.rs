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
    if fs::symlink_metadata(&path).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        anyhow::bail!("{} is a symlink; refusing to write a secret through it", path.display());
    }
    if is_git_tracked(project, &path) {
        anyhow::bail!(
            "{} is tracked by git, so .gitignore cannot keep it out of the next commit. Run `git rm --cached {}` (keeps the local file) and re-run.",
            path.display(), env_file
        );
    }
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
    // Ignore protection is confirmed BEFORE the secret lands: if .gitignore cannot be
    // safely updated, nothing is written.
    ensure_gitignore(project, env_file)?;
    // Atomic, 0600 from the first byte, and refuses a symlinked env file so a project
    // cannot redirect secret writes to an arbitrary target.
    crate::fsutil::write_atomic_private(&path, &out).with_context(|| format!("writing {}", path.display()))?;
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

/// Git semantics: rules are evaluated in order and the LAST matching rule wins, so a later
/// `!name` re-includes the file. We fold over the lines tracking that state. Anything we
/// cannot evaluate (directory rules, path-anchored patterns) neither covers nor uncovers.
/// Conservative: when the final state is not "ignored", append an explicit rule at the
/// end, which then wins.
pub fn gitignore_covers(contents: &str, file: &str) -> bool {
    let mut ignored = false;
    for raw in contents.lines() {
        // git ignores TRAILING whitespace (unless escaped) but leading whitespace is part
        // of the pattern, so " .env.local" does not match ".env.local".
        let l = raw.trim_end_matches([' ', '\t', '\r']);
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let (negated, pat) = match l.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, l),
        };
        if let Some(m) = ignore_line_matches(pat, file) {
            if m {
                ignored = !negated;
            }
        }
    }
    ignored
}

/// Does one (un-negated) pattern apply to `file`, a bare filename at any depth?
/// Returns None when the rule is not evaluable (directory rule, path-anchored pattern).
fn ignore_line_matches(pat: &str, file: &str) -> Option<bool> {
    if pat.ends_with('/') {
        return None;
    }
    let pat = pat.strip_prefix('/').unwrap_or(pat);
    if pat.contains('/') {
        return None;
    }
    Some(glob_match(pat, file))
}

/// Convenience for a single positive line (kept for callers/tests).
pub fn ignore_line_covers(line: &str, file: &str) -> bool {
    gitignore_covers(line, file)
}

fn glob_match(pat: &str, s: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    let (mut pi, mut si, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while si < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[si]) {
            pi += 1; si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi); mark = si; pi += 1;
        } else if let Some(st) = star {
            pi = st + 1; mark += 1; si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' { pi += 1; }
    pi == p.len()
}

/// Is this path in the git index? An ignore rule does nothing for a file that is already
/// tracked. Best effort: if git cannot be run, assume not tracked (the .gitignore path
/// still applies).
pub fn is_git_tracked(project: &Path, path: &Path) -> bool {
    let Some(root) = git_root(project) else { return false };
    let Ok(rel) = path.strip_prefix(&root) else { return false };
    std::process::Command::new("git")
        .arg("-C").arg(&root)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(rel)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|st| st.success())
        .unwrap_or(false)
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

/// If inside a git repo, make sure the env file is ignored. We add a rule to the root
/// `.gitignore` if our own evaluation says it is not covered, then ask git itself
/// (`git check-ignore`) for the effective answer — a nested `.gitignore` closer to the
/// project can re-include the file. If git says it is still not ignored, a rule is added to
/// the project's own `.gitignore` (closest wins) and re-verified; if that still fails, the
/// caller must not write the secret. Symlinked ignore files are refused.
pub fn ensure_gitignore(project: &Path, env_file: &str) -> Result<bool> {
    let Some(root) = git_root(project) else { return Ok(false) };
    let mut changed = add_rule_if_uncovered(&root.join(".gitignore"), env_file)?;
    let target = project.join(env_file);
    match git_check_ignore(&root, &target) {
        Some(true) | None => Ok(changed),
        Some(false) => {
            // a closer .gitignore re-includes it; the project's own file is closest
            let local = project.join(".gitignore");
            if local != root.join(".gitignore") {
                changed |= add_rule_if_uncovered(&local, env_file)?;
                if !gitignore_covers(&fs::read_to_string(&local).unwrap_or_default(), env_file) {
                    // covered-by-our-evaluation but still re-included means a later negation
                    // in this same file; append an explicit trailing rule regardless.
                    append_rule(&local, env_file)?;
                    changed = true;
                }
            }
            match git_check_ignore(&root, &target) {
                Some(false) => anyhow::bail!("git still does not ignore {} after updating .gitignore (a nested rule re-includes it); refusing to write a secret there", target.display()),
                _ => Ok(changed),
            }
        }
    }
}

/// Ask git for the effective ignore decision. None if git cannot be run.
pub fn git_check_ignore(root: &Path, path: &Path) -> Option<bool> {
    let rel = path.strip_prefix(root).ok()?;
    let st = std::process::Command::new("git")
        .arg("-C").arg(root)
        .args(["check-ignore", "-q", "--no-index", "--"])
        .arg(rel)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;
    match st.code() {
        Some(0) => Some(true),
        Some(1) => Some(false),
        _ => None,
    }
}

fn append_rule(gi: &Path, env_file: &str) -> Result<()> {
    if fs::symlink_metadata(gi).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        anyhow::bail!("{} is a symlink; refusing to modify it", gi.display());
    }
    let mut s = fs::read_to_string(gi).unwrap_or_default();
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s.push_str("# added by tokenstash — never commit injected secrets\n");
    s.push_str(env_file);
    s.push('\n');
    crate::fsutil::write_atomic(gi, &s)
}

/// Add a rule to one ignore file if our evaluation says the name is not covered.
fn add_rule_if_uncovered(gi: &Path, env_file: &str) -> Result<bool> {
    if fs::symlink_metadata(gi).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        anyhow::bail!("{} is a symlink; refusing to modify it (and cannot guarantee {env_file} stays uncommitted)", gi.display());
    }
    let existing = if gi.exists() { fs::read_to_string(gi)? } else { String::new() };
    if gitignore_covers(&existing, env_file) {
        return Ok(false);
    }
    let mut s = existing;
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s.push_str("# added by tokenstash — never commit injected secrets\n");
    s.push_str(env_file);
    s.push('\n');
    crate::fsutil::write_atomic(gi, &s)?;
    Ok(true)
}
