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
}

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
        }
    }
}

/// `$TOKENSTASH_HOME` or `~/.config/tokenstash`.
pub fn config_dir() -> PathBuf {
    if let Ok(p) = std::env::var("TOKENSTASH_HOME") {
        return PathBuf::from(p);
    }
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
        Ok(toml::from_str(&s).with_context(|| format!("parsing {}", p.display()))?)
    }

    pub fn save(&self) -> Result<()> {
        let dir = config_dir();
        fs::create_dir_all(&dir)?;
        restrict_dir(&dir);
        fs::write(config_path(), toml::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn exists() -> bool { config_path().exists() }

    /// Sensible defaults for trust roots: common code dirs that exist, plus cwd.
    pub fn default_trust_roots() -> Vec<PathBuf> {
        let home = dirs::home_dir().unwrap_or_default();
        let mut v: Vec<PathBuf> = ["code", "projects", "dev", "src", "repos", "work"]
            .iter()
            .map(|d| home.join(d))
            .filter(|p| p.is_dir())
            .collect();
        if let Ok(cwd) = std::env::current_dir() {
            if !v.iter().any(|r| cwd.starts_with(r)) {
                v.push(cwd);
            }
        }
        v
    }
}

#[cfg(unix)]
fn restrict_dir(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn restrict_dir(_p: &Path) {}
