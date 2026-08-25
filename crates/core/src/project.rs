//! Project identity and caller detection.

use std::path::{Path, PathBuf};

/// Canonical project id: git root if inside a repo, else the directory itself.
pub fn canonical(dir: &Path) -> PathBuf {
    let abs = if dir.is_absolute() { dir.to_path_buf() } else { std::env::current_dir().unwrap_or_default().join(dir) };
    let abs = abs.canonicalize().unwrap_or(abs);
    // A foreign-owned checkout still resolves to itself here so the write path can refuse
    // it with a clear error; a shared ancestor (/tmp) is never adopted as the project.
    crate::envfile::owned_git_root(&abs).ok().flatten().unwrap_or(abs)
}

pub fn current() -> PathBuf {
    canonical(&std::env::current_dir().unwrap_or_default())
}

/// Best-effort agent detection from the environment.
pub fn detect_agent() -> String {
    if let Ok(a) = std::env::var("TOKENSTASH_AGENT") {
        return a;
    }
    let has = |k: &str| std::env::var_os(k).is_some();
    if has("CLAUDECODE") || has("CLAUDE_CODE_ENTRYPOINT") {
        return "claude-code".into();
    }
    if has("CODEX_SANDBOX") || has("CODEX_CI") || has("OPENAI_CODEX") {
        return "codex".into();
    }
    if has("CURSOR_TRACE_ID") || has("CURSOR_AGENT") {
        return "cursor".into();
    }
    if has("GEMINI_CLI") {
        return "gemini-cli".into();
    }
    if has("OPENCODE") {
        return "opencode".into();
    }
    "unknown".into()
}

pub fn short(p: &Path) -> String {
    if let Some(home) = dirs::home_dir() {
        if let Ok(rest) = p.strip_prefix(&home) {
            return format!("~/{}", rest.display());
        }
    }
    p.display().to_string()
}
