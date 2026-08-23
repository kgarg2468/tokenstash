//! tokenstash core: stash adapter, task queue, registry, env injection, trust.
//!
//! Invariant: nothing in this crate ever returns a secret value on a path that
//! reaches stdout/stderr/logs. Values move clipboard → keychain → env file.

pub mod config;
pub mod db;
pub mod redact;
pub mod registry;
pub mod stash;
pub mod validate;


pub use config::Config;
pub use db::Db;

/// Exit codes shared by CLI and MCP wrapper.
pub mod exit {
    pub const INJECTED: i32 = 0;
    pub const ERROR: i32 = 1;
    pub const PENDING: i32 = 10;
    pub const DENIED: i32 = 20;
    pub const EXPIRED: i32 = 30;
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
