use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Directories whose projects get silent injection of non-sensitive keys.
    #[serde(default)]
    pub trust_roots: Vec<PathBuf>,
    /// Env file name written into projects.
    #[serde(default = "default_env_file")]
    pub env_file: String,
    /// Localhost inbox port.
    #[serde(default = "default_port")]
    pub inbox_port: u16,
    /// Hours until an unanswered task expires.
    #[serde(default = "default_ttl")]
    pub task_ttl_hours: u64,
    /// Stash backend override: "keyring" | "keyutils" | "insecure-file".
    #[serde(default)]
    pub stash_backend: Option<String>,
    /// Whether to show desktop notifications.
    #[serde(default = "default_true")]
    pub notifications: bool,
    /// Which inbox session agent-facing links carry: "paste" (default: the link can answer
    /// missing-key cards but not approve) or "full" (the link can do everything).
    #[serde(default = "default_links")]
    pub inbox_links: String,
}

fn default_links() -> String { "paste".into() }

fn default_env_file() -> String { ".env.local".into() }
fn default_port() -> u16 { 7433 }
fn default_ttl() -> u64 { 24 }
fn default_true() -> bool { true }

impl Default for Config {
    fn default() -> Self {
        Self {
            trust_roots: vec![],
            env_file: default_env_file(),
            inbox_port: default_port(),
            task_ttl_hours: default_ttl(),
            stash_backend: None,
            notifications: true,
            inbox_links: default_links(),
        }
    }
}

/// `$TOKENSTASH_HOME` or the default.
pub fn config_dir() -> PathBuf {
    if let Ok(p) = std::env::var("TOKENSTASH_HOME") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    default_config_dir()
}

/// The default home, ignoring `TOKENSTASH_HOME`: `~/.config/tokenstash` on Linux,
/// `~/Library/Application Support/tokenstash` on macOS. For state that is about the machine
/// rather than one home (the init undo manifest).
pub fn default_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| dirs::home_dir().expect("no home dir").join(".config"))
        .join("tokenstash")
}

pub fn config_path() -> PathBuf { config_dir().join("config.toml") }
pub fn db_path() -> PathBuf { config_dir().join("tokenstash.db") }

impl Config {
    pub fn load() -> Result<Self> {
        let p = config_path();
        if !p.exists() {
            return Ok(Self::default());
        }
        let s = fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        toml::from_str(&s).with_context(|| format!("parsing {}", p.display()))
    }

    pub fn save(&self) -> Result<()> {
        let dir = config_dir();
        fs::create_dir_all(&dir)?;
        restrict_dir(&dir);
        fs::write(config_path(), toml::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn exists() -> bool { config_path().exists() }

    /// Guessed trust roots: common code dirs under $HOME that exist. Never the current
    /// directory — `init` is run from wherever the binary happens to be (a clone of this
    /// repo, a scratch dir, an agent's worktree), and a guess must not turn that into a
    /// place secrets flow silently.
    pub fn default_trust_roots() -> Vec<PathBuf> {
        let home = dirs::home_dir().unwrap_or_default();
        ["code", "projects", "dev", "src", "repos", "work"]
            .iter()
            .map(|d| home.join(d))
            .filter(|p| p.is_dir())
            .collect()
    }
}

#[cfg(unix)]
fn restrict_dir(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn restrict_dir(_p: &Path) {}
