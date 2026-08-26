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
use std::path::{Component, Path, PathBuf};

/// Resolve `<project>/<env_file>` for writing, refusing any value that lands the secret
/// outside the project directory.
///
/// `env_file` is configuration, and every protection below (gitignore coverage, the
/// tracked-file check) is anchored on the project, so a path that escapes it is a secret
/// written with no protection at all. Three ways out, all closed here: an absolute path, a
/// `..` component, and a parent directory that is a symlink pointing out of the project.
/// Validate the configured `env_file` spelling and return it normalized (`./` components
/// dropped) so the gitignore rule and the on-disk path agree. Refuses absolute paths,
/// roots, and `..`.
pub fn normalize(env_file: &str) -> Result<String> {
    let rel = Path::new(env_file);
    if env_file.is_empty() || rel.is_absolute() || rel.has_root() {
        anyhow::bail!("env_file must be a relative path inside the project, but is '{env_file}'");
    }
    let mut parts = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(p) => parts.push(p.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => anyhow::bail!("env_file must be a plain relative path inside the project (no '..', no leading '/'), but is '{env_file}'"),
        }
    }
    if parts.is_empty() {
        anyhow::bail!("env_file must name a file inside the project, but is '{env_file}'");
    }
    Ok(parts.join("/"))
}

pub fn resolve(project: &Path, env_file: &str) -> Result<PathBuf> {
    let norm = normalize(env_file)?;
    let rel = Path::new(&norm);
    // Anchor on the canonical project so a symlinked prefix of the project itself
    // (/tmp → /private/tmp on macOS) is not mistaken for an escape.
    let base = project.canonicalize().unwrap_or_else(|_| project.to_path_buf());
    // The containment check runs on canonical paths, but the returned path stays under the
    // caller's `project` spelling: `is_git_tracked` / `git check-ignore` run with `project` as
    // cwd, and a canonical spelling (/private/var/... on macOS) would look like a path outside
    // the repo to git and silently defeat the tracked-file refusal.
    let path = project.join(rel);
    // The parent may not exist yet; the deepest existing ancestor is where a symlink could
    // redirect the write, and it is the only part we can resolve.
    let mut anchor = base.join(rel).parent().unwrap_or(&base).to_path_buf();
    while !anchor.exists() && anchor.pop() {}
    let real = anchor.canonicalize().with_context(|| format!("resolving {}", anchor.display()))?;
    if !real.starts_with(&base) {
        anyhow::bail!(
            "env_file '{env_file}' resolves outside the project: {} is not inside {}; refusing to write a secret there",
            real.display(), base.display()
        );
    }
    Ok(path)
}

/// Upsert `NAME=value` into `<project>/<env_file>`. Preserves other lines. 0600.
pub fn write(project: &Path, env_file: &str, name: &str, value: &SecretString) -> Result<PathBuf> {
    let env_file = &normalize(env_file)?;
    let path = resolve(project, env_file)?;
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
    let Ok(path) = resolve(project, env_file) else { return false };
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
    // A quoted value ends at its closing quote; whatever follows (a trailing comment) is
    // ignored. An unquoted value ends at a `#` that follows whitespace — a `#` inside a
    // token (a password in a URL) is part of the value, as dotenv reads it.
    let val = if let Some(inner) = v.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = inner.chars();
        let mut closed = false;
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some('n') => out.push('\n'),
                    Some(o) => out.push(o),
                    None => out.push('\\'),
                },
                '"' => { closed = true; break; }
                _ => out.push(c),
            }
        }
        if !closed { return None; } // an unterminated (multi-line) value is not one line's worth
        out
    } else if let Some(inner) = v.strip_prefix('\'') {
        let end = inner.find('\'')?;
        inner[..end].to_string()
    } else {
        let mut end = v.len();
        for (i, c) in v.char_indices() {
            if c == '#' && (i == 0 || v[..i].ends_with(|w: char| w.is_whitespace())) { end = i; break; }
        }
        v[..end].trim().to_string()
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
    // Detection, not policy: a tracked file is refused wherever the repo lives.
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
/// Nearest ancestor (or `start` itself) that holds a `.git` — plain detection, no policy.
/// Callers that decide where to WRITE use [`owned_git_root`].
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

/// The git root a project may be resolved to and written into. Walks up like [`git_root`]
/// with two rules git itself does not apply:
/// - a sticky / world-writable directory (`/tmp`, `/var/tmp`) is never a root and ends the
///   walk: a stray `.git` there (one `git init` from the wrong cwd is enough) would make every
///   project under it resolve to `/tmp`, and the env file and `.gitignore` would be written
///   there. Seen for real by the leak test. `Ok(None)`: treat the directory as its own project.
/// - a `.git` in a directory the current user does not own is an ERROR, not "no repo": the
///   checkout is real, so tracked-file and gitignore protection still apply, but we cannot
///   write the ignore rule into someone else's tree. Failing closed here means a shared or
///   root-owned checkout never silently loses its git safeguards.
pub fn owned_git_root(start: &Path) -> Result<Option<PathBuf>> {
    let mut p = start.to_path_buf();
    loop {
        let has_git = p.join(".git").exists();
        match dir_class(&p) {
            DirClass::Shared => return Ok(None),
            DirClass::Foreign if has_git => anyhow::bail!(
                "{} is a git checkout owned by another user; refusing to write a secret into a tree whose .gitignore is not yours",
                p.display()
            ),
            DirClass::Foreign => return Ok(None),
            DirClass::Own if has_git => return Ok(Some(p)),
            DirClass::Own => {}
        }
        if !p.pop() {
            return Ok(None);
        }
    }
}

enum DirClass {
    /// Owned by the current user, not sticky/world-writable.
    Own,
    /// Sticky or world-writable: /tmp and friends. Never a project root.
    Shared,
    /// Owned by someone else.
    Foreign,
}

#[cfg(unix)]
fn dir_class(p: &Path) -> DirClass {
    use std::os::unix::fs::MetadataExt;
    let Ok(md) = fs::metadata(p) else { return DirClass::Foreign };
    if md.mode() & 0o1002 != 0 {
        return DirClass::Shared;
    }
    if md.uid() == unsafe { libc_geteuid() } { DirClass::Own } else { DirClass::Foreign }
}
#[cfg(not(unix))]
fn dir_class(_p: &Path) -> DirClass { DirClass::Own }

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    extern "C" { fn geteuid() -> u32; }
    geteuid()
}

/// If inside a git repo, make sure the env file is ignored. We add a rule to the root
/// `.gitignore` if our own evaluation says it is not covered, then ask git itself
/// (`git check-ignore`) for the effective answer — a nested `.gitignore` closer to the
/// project can re-include the file. If git says it is still not ignored, a rule is added to
/// the project's own `.gitignore` (closest wins) and re-verified; if that still fails, the
/// caller must not write the secret. Symlinked ignore files are refused.
pub fn ensure_gitignore(project: &Path, env_file: &str) -> Result<bool> {
    let Some(root) = owned_git_root(project)? else { return Ok(false) };
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
