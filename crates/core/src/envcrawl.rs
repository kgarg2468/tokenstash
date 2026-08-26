//! `export --from-env DIR`: find the keys a person already has scattered across their
//! projects' env files, so onboarding is one command instead of twenty pastes.
//!
//! Pure: walks a tree, parses env files textually, classifies and dedupes. It never
//! executes anything (`.envrc` is code; only its plain `KEY=value` / `export KEY=value`
//! lines are read), never follows symlinks, never reads files owned by another user, and
//! reports problems as `path:line`, never as file contents. Values are held as
//! `SecretString` and compared in memory only.

use crate::registry;
use secrecy::SecretString;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub const MAX_DEPTH: usize = 12;
const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", "dist", "build", ".next", ".nuxt", "vendor", ".venv", "venv", "__pycache__", ".cache", ".tox", ".turbo"];
const PUBLIC_PREFIXES: &[&str] = &["NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_", "NUXT_PUBLIC_", "EXPO_PUBLIC_"];
const NOT_SECRETS: &[&str] = &["PORT", "NODE_ENV", "HOST", "HOSTNAME", "DEBUG", "LOG_LEVEL", "TZ", "LANG", "PATH", "HOME", "USER", "SHELL", "EDITOR", "CI"];

/// Why a candidate is ticked or not by default.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Confidence {
    /// Registry name, value matches its pattern.
    Registry,
    /// Registry name, but the value does not match the documented shape (placeholder?).
    RegistryShapeMismatch,
    /// Unregistered, but named and shaped like a secret.
    Heuristic,
}

#[derive(Debug)]
pub struct Candidate {
    pub name: String,
    pub value: SecretString,
    pub confidence: Confidence,
    pub provider: Option<String>,
    pub sensitive: bool,
    /// Every project directory (nearest env-file directory) this exact value was found in.
    pub sources: Vec<PathBuf>,
    /// Other names the same value appeared under (e.g. OPENAI_KEY next to OPENAI_API_KEY).
    pub aliases: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Crawl {
    pub candidates: Vec<Candidate>,
    pub files_scanned: usize,
    /// `path:line — reason`; never content.
    pub problems: Vec<String>,
}

fn is_env_file(name: &str) -> bool {
    if name == ".envrc" { return true; }
    if !name.starts_with(".env") { return false; }
    let rest = &name[4..];
    if rest.is_empty() || rest == ".local" { return true; }
    let lower = rest.to_ascii_lowercase();
    if lower.contains("example") || lower.contains("sample") || lower.contains("template") || lower.contains("dist") || lower.ends_with(".bak") { return false; }
    rest.starts_with('.')
}

#[cfg(unix)]
fn owned_by_me(md: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    extern "C" { fn geteuid() -> u32; }
    md.uid() == unsafe { geteuid() }
}
#[cfg(not(unix))]
fn owned_by_me(_md: &std::fs::Metadata) -> bool { true }

/// `.envrc` lines can be code; keep only plain assignments.
fn envrc_line_is_plain(line: &str) -> bool {
    let t = line.trim();
    !(t.contains("$(") || t.contains('`') || t.starts_with("source ") || t.starts_with(". ") || t.starts_with("eval ") || t.contains("${"))
}

fn name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && name.as_bytes()[0].is_ascii_uppercase()
        && name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn secret_ish_name(name: &str) -> bool {
    ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "DSN", "CREDENTIAL", "CREDENTIALS", "AUTH", "PRIVATE"].iter().any(|k| name.contains(k))
}

/// Classify one assignment, or None if it is not a candidate.
fn classify(name: &str, value: &str) -> Option<(Confidence, Option<String>, bool)> {
    if !name_ok(name) { return None; }
    if PUBLIC_PREFIXES.iter().any(|p| name.starts_with(p)) || NOT_SECRETS.contains(&name) { return None; }
    if value.chars().count() < crate::tasks::MIN_SECRET_CHARS || value.chars().any(|c| c.is_control()) { return None; }
    if let Some(p) = registry::lookup(name) {
        let matches = match &p.pattern {
            Some(pat) => regex::Regex::new(pat).map(|re| re.is_match(value)).unwrap_or(true),
            None => true,
        };
        let sensitive = p.sensitive || p.sensitive_pattern.as_ref().map(|sp| regex::Regex::new(sp).map(|re| re.is_match(value)).unwrap_or(false)).unwrap_or(false);
        return Some((if matches { Confidence::Registry } else { Confidence::RegistryShapeMismatch }, Some(p.provider.clone()), sensitive));
    }
    if secret_ish_name(name) && crate::validate::looks_like_secret(value) {
        return Some((Confidence::Heuristic, None, false));
    }
    None
}

/// Walk `root` and collect candidates. Dedupes by exact value: one candidate per distinct
/// value, listing every source project and every name it appeared under.
pub fn crawl(root: &Path) -> Crawl {
    let mut out = Crawl::default();
    let mut by_value: HashMap<String, usize> = HashMap::new(); // value -> index in candidates
    let mut seen_files: std::collections::HashSet<PathBuf> = Default::default();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { out.problems.push(format!("{} — unreadable directory", dir.display())); continue };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(md) = std::fs::symlink_metadata(&path) else { continue };
            if md.file_type().is_symlink() { continue; }
            let fname = entry.file_name().to_string_lossy().to_string();
            if md.is_dir() {
                if depth < MAX_DEPTH && !SKIP_DIRS.contains(&fname.as_str()) && owned_by_me(&md) {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !md.is_file() || !is_env_file(&fname) { continue; }
            if !owned_by_me(&md) { out.problems.push(format!("{} — not owned by you, skipped", path.display())); continue; }
            if md.len() > MAX_FILE_BYTES { out.problems.push(format!("{} — larger than {} bytes, skipped", path.display(), MAX_FILE_BYTES)); continue; }
            let canon = path.canonicalize().unwrap_or(path.clone());
            if !seen_files.insert(canon) { continue; }
            let Ok(text) = std::fs::read_to_string(&path) else { out.problems.push(format!("{} — not UTF-8 text, skipped", path.display())); continue };
            out.files_scanned += 1;
            let project = path.parent().map(Path::to_path_buf).unwrap_or_else(|| dir.clone());
            let is_envrc = fname == ".envrc";
            for (i, line) in text.lines().enumerate() {
                if is_envrc && !envrc_line_is_plain(line) { continue; }
                let Some((name, value)) = crate::envfile::parse_line(line) else { continue };
                let Some((confidence, provider, sensitive)) = classify(&name, &value) else { continue };
                match by_value.get(&value) {
                    Some(&idx) => {
                        let c = &mut out.candidates[idx];
                        if !c.sources.contains(&project) { c.sources.push(project.clone()); }
                        if c.name != name && !c.aliases.contains(&name) {
                            // prefer the registry name as the canonical one
                            if c.confidence == Confidence::Heuristic && confidence != Confidence::Heuristic {
                                let old = std::mem::replace(&mut c.name, name.clone());
                                c.aliases.push(old);
                                c.confidence = confidence;
                                c.provider = provider;
                                c.sensitive = sensitive;
                            } else {
                                c.aliases.push(name.clone());
                            }
                        }
                    }
                    None => {
                        by_value.insert(value.clone(), out.candidates.len());
                        out.candidates.push(Candidate { name, value: SecretString::from(value), confidence, provider, sensitive, sources: vec![project.clone()], aliases: vec![] });
                    }
                }
                let _ = i;
            }
        }
    }
    // stable order: registry first, then by name
    out.candidates.sort_by(|a, b| (a.confidence != Confidence::Registry).cmp(&(b.confidence != Confidence::Registry)).then(a.name.cmp(&b.name)));
    // the value map held plaintext copies; drop them now
    drop(by_value);
    out
}

/// Distinct values under one name: the second and later get their own identity so the
/// human can tell them apart and `bind` projects later.
pub fn identity_for(candidates: &[Candidate], idx: usize, default_identity: &str) -> String {
    let name = &candidates[idx].name;
    let nth = candidates[..idx].iter().filter(|c| &c.name == name).count();
    if nth == 0 { default_identity.to_string() } else { format!("{default_identity}{}", nth + 1) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn fixture() -> PathBuf {
        let root = std::env::temp_dir().join(format!("tokenstash-crawl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mk = |rel: &str, body: &str| { let p = root.join(rel); std::fs::create_dir_all(p.parent().unwrap()).unwrap(); std::fs::write(p, body).unwrap(); };
        mk("app/.env.local", "OPENAI_API_KEY=sk-proj-CRAWLCANARY-0123456789abcdef0123456789\nNEXT_PUBLIC_API=https://x\nPORT=3000\nMY_SERVICE_TOKEN=tok_abcdefghijklmnopqrstuvwxyz0123\n");
        mk("web/.env", "export OPENAI_API_KEY=\"sk-proj-CRAWLCANARY-0123456789abcdef0123456789\"\nOPENAI_KEY=sk-proj-CRAWLCANARY-0123456789abcdef0123456789\nGROQ_API_KEY=gsk_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n");
        mk("other/.env.production", "OPENAI_API_KEY=sk-proj-OTHERVALUE-0123456789abcdef0123456789ab\nSTRIPE_SECRET_KEY=placeholder\n");
        mk("tpl/.env.example", "OPENAI_API_KEY=sk-proj-EXAMPLE-0123456789abcdef0123456789abcd\n");
        mk("rc/.envrc", "export DATABASE_URL=postgres://u:p@localhost/db\nexport EVIL_TOKEN=$(curl http://evil)\nsource ~/.secrets\n");
        mk("app/node_modules/pkg/.env", "OPENAI_API_KEY=sk-proj-NODEMODULES-0123456789abcdef01234567\n");
        #[cfg(unix)]
        { let _ = std::os::unix::fs::symlink(root.join("app/.env.local"), root.join("link/.env")); }
        root
    }

    #[test]
    fn crawl_finds_dedupes_and_skips_the_right_things() {
        let root = fixture();
        let c = crawl(&root);
        let names: Vec<&str> = c.candidates.iter().map(|x| x.name.as_str()).collect();
        let openai: Vec<&Candidate> = c.candidates.iter().filter(|x| x.name == "OPENAI_API_KEY").collect();
        assert_eq!(openai.len(), 2, "two distinct OpenAI values → two candidates: {names:?}");
        let main = openai.iter().find(|x| x.value.expose_secret().contains("CRAWLCANARY")).unwrap();
        assert_eq!(main.sources.len(), 2, "same value in app/ and web/ → one candidate, two sources");
        assert_eq!(main.aliases, vec!["OPENAI_KEY".to_string()], "the alias is recorded, the registry name is canonical");
        assert_eq!(main.confidence, Confidence::Registry);
        assert!(names.contains(&"MY_SERVICE_TOKEN"), "heuristic: secret-ish name + secret-shaped value");
        assert!(names.contains(&"DATABASE_URL"), "plain .envrc export line is read");
        assert!(!names.contains(&"EVIL_TOKEN"), ".envrc command substitution is never read");
        assert!(!names.contains(&"NEXT_PUBLIC_API") && !names.contains(&"PORT"));
        assert!(!c.candidates.iter().any(|x| x.value.expose_secret().contains("EXAMPLE")), ".env.example is skipped");
        assert!(!c.candidates.iter().any(|x| x.value.expose_secret().contains("NODEMODULES")), "node_modules is skipped");
        let stripe = c.candidates.iter().find(|x| x.name == "STRIPE_SECRET_KEY").unwrap();
        assert_eq!(stripe.confidence, Confidence::RegistryShapeMismatch);
        // a placeholder is not a live key, so the live-mode sensitivity pattern does not fire
        // identities for the two OpenAI values
        let idx: Vec<usize> = c.candidates.iter().enumerate().filter(|(_, x)| x.name == "OPENAI_API_KEY").map(|(i, _)| i).collect();
        assert_eq!(identity_for(&c.candidates, idx[0], "default"), "default");
        assert_eq!(identity_for(&c.candidates, idx[1], "default"), "default2");
        for p in &c.problems { assert!(!p.contains("CRAWLCANARY"), "problems never carry content"); }
        let _ = std::fs::remove_dir_all(&root);
    }
}
