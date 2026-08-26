//! Provider registry: how to acquire a key for a given env var name.
//! Embedded at build time from `registry/providers.json`; meant to move to its own repo.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

const RAW: &str = include_str!("../../../registry/providers.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    /// GET | POST
    #[serde(default = "default_get")]
    pub method: String,
    pub url: String,
    /// "bearer" | "header:<Name>" | "basic-user" (value as username, empty password) | "query:<param>"
    pub auth: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Extra statuses that mean "this credential was rejected", for providers whose
    /// documented auth-failure code is not 401/403. Google returns 400
    /// INVALID_ARGUMENT for a bad API key, Brave returns 422. Without this the probe
    /// is decorative: `liveness` treats every other status as "accept".
    #[serde(default)]
    pub reject_status: Vec<u16>,
    /// May this probe run unattended every time an agent `need`s the key (verify-on-use)?
    /// An explicit allowlist, not a default: a probe is only safe at use when it is free
    /// (no quota, no billing), read-only, and 401 unambiguously means "dead key". Off for
    /// metered endpoints (Brave burns a search), for providers whose reject code is a
    /// generic 400 (a bad request looks like a bad key), and for endpoints that answer 200
    /// for an expired token and put the verdict in the body (Cloudflare).
    #[serde(default)]
    pub at_use: bool,
}
fn default_get() -> String { "GET".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    /// Env var name, e.g. OPENAI_API_KEY
    pub name: String,
    /// Human label, e.g. "OpenAI"
    pub provider: String,
    /// Where to sign up / create the key.
    pub url: String,
    #[serde(default)]
    pub dashboard: Option<String>,
    #[serde(default)]
    pub steps: Vec<String>,
    /// Regex the value must match.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Always prompt once per project.
    #[serde(default)]
    pub sensitive: bool,
    /// Prompt once per project only if the value matches (e.g. live vs test keys).
    #[serde(default)]
    pub sensitive_pattern: Option<String>,
    #[serde(default)]
    pub check: Option<Check>,
    /// Other env vars that usually travel with this one.
    #[serde(default)]
    pub companions: Vec<String>,
    /// Local secrets that need no human: "base64:32" | "hex:32".
    #[serde(default)]
    pub generate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegistryFile {
    providers: Vec<Provider>,
}

fn table() -> &'static HashMap<String, Provider> {
    static T: OnceLock<HashMap<String, Provider>> = OnceLock::new();
    T.get_or_init(|| {
        let f: RegistryFile = serde_json::from_str(RAW).expect("registry/providers.json is invalid");
        f.providers.into_iter().map(|p| (p.name.clone(), p)).collect()
    })
}

pub fn lookup(name: &str) -> Option<&'static Provider> {
    table().get(name)
}

pub fn all() -> Vec<&'static Provider> {
    let mut v: Vec<_> = table().values().collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

pub fn count() -> usize {
    table().len()
}
