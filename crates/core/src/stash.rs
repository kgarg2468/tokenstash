//! Stash adapter: where secret values live. Metadata lives in the DB; values live here.
//!
//! Backends:
//!
//! - `keyring`: OS store via the `keyring` crate (macOS Keychain, Windows Credential Manager,
//!   Linux Secret Service). Default.
//! - `keyutils`: Linux kernel keyring (no daemon needed; survives logout, not reboot).
//!   Auto-selected on Linux when Secret Service is unavailable.
//! - `insecure-file`: 0600 JSON file. ONLY for CI/tests. Requires explicit opt-in via
//!   `TOKENSTASH_STASH=insecure-file` or config. Prints a warning.

use anyhow::{anyhow, Result};
use secrecy::{ExposeSecret, SecretString};
use std::collections::BTreeMap;
use std::path::PathBuf;

const SERVICE: &str = "tokenstash";

pub trait Stash {
    fn backend(&self) -> &'static str;
    fn get(&self, key: &str) -> Result<Option<SecretString>>;
    fn set(&self, key: &str, value: &SecretString) -> Result<()>;
    fn delete(&self, key: &str) -> Result<bool>;
}

/// Stash key format: `NAME@identity`. Decided day one so identities never need a migration.
pub fn stash_key(name: &str, identity: &str) -> String {
    format!("{name}@{identity}")
}

pub fn open(cfg: &crate::Config) -> Result<Box<dyn Stash>> {
    let backend = std::env::var("TOKENSTASH_STASH")
        .ok()
        .or_else(|| cfg.stash_backend.clone())
        .unwrap_or_else(|| "auto".into());
    match backend.as_str() {
        "insecure-file" => {
            eprintln!("tokenstash: WARNING — using insecure-file stash (plaintext, 0600). For CI/tests only.");
            Ok(Box::new(FileStash::new()?))
        }
        "keyring" => Ok(Box::new(KeyringStash::os_store()?)),
        #[cfg(target_os = "linux")]
        "keyutils" => Ok(Box::new(KeyringStash::keyutils()?)),
        "auto" => KeyringStash::auto().map(|s| Box::new(s) as Box<dyn Stash>),
        other => Err(anyhow!("unknown stash backend '{other}'")),
    }
}

// ---------------- keyring-backed ----------------

pub struct KeyringStash {
    name: &'static str,
}

impl KeyringStash {
    /// Platform OS store (Keychain / Credential Manager / Secret Service).
    pub fn os_store() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            keyring::set_default_credential_builder(keyring::secret_service::default_credential_builder());
            return Ok(Self { name: "secret-service" });
        }
        #[allow(unreachable_code)]
        Ok(Self { name: "os-keychain" })
    }

    #[cfg(target_os = "linux")]
    pub fn keyutils() -> Result<Self> {
        keyring::set_default_credential_builder(keyring::keyutils::default_credential_builder());
        Ok(Self { name: "keyutils" })
    }

    /// OS store if it works; on Linux fall back to the kernel keyring.
    pub fn auto() -> Result<Self> {
        let s = Self::os_store()?;
        if s.probe().is_ok() {
            return Ok(s);
        }
        #[cfg(target_os = "linux")]
        {
            let k = Self::keyutils()?;
            k.probe().map_err(|e| anyhow!("no usable Linux keyring (Secret Service unavailable and keyutils failed): {e}"))?;
            return Ok(k);
        }
        #[allow(unreachable_code)]
        Err(anyhow!("OS keychain unavailable"))
    }

    /// Round-trip a throwaway entry to confirm the backend works.
    pub fn probe(&self) -> Result<()> {
        let key = "__tokenstash_probe__";
        let e = keyring::Entry::new(SERVICE, key)?;
        e.set_password("ok")?;
        let got = e.get_password()?;
        let _ = e.delete_credential();
        if got != "ok" {
            return Err(anyhow!("probe mismatch"));
        }
        Ok(())
    }
}

impl Stash for KeyringStash {
    fn backend(&self) -> &'static str {
        self.name
    }
    fn get(&self, key: &str) -> Result<Option<SecretString>> {
        let e = keyring::Entry::new(SERVICE, key)?;
        match e.get_password() {
            Ok(v) => Ok(Some(SecretString::from(v))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(anyhow!("keyring read failed: {err}")),
        }
    }
    fn set(&self, key: &str, value: &SecretString) -> Result<()> {
        let e = keyring::Entry::new(SERVICE, key)?;
        e.set_password(value.expose_secret()).map_err(|err| anyhow!("keyring write failed: {err}"))
    }
    fn delete(&self, key: &str) -> Result<bool> {
        let e = keyring::Entry::new(SERVICE, key)?;
        match e.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(anyhow!("keyring delete failed: {err}")),
        }
    }
}

// ---------------- insecure file (tests/CI only) ----------------

pub struct FileStash {
    path: PathBuf,
}

impl FileStash {
    pub fn new() -> Result<Self> {
        let path = crate::config::config_dir().join("insecure-stash.json");
        std::fs::create_dir_all(path.parent().unwrap())?;
        Ok(Self { path })
    }
    fn read(&self) -> Result<BTreeMap<String, String>> {
        if !self.path.exists() {
            return Ok(BTreeMap::new());
        }
        let s = std::fs::read_to_string(&self.path)?;
        Ok(serde_json::from_str(&s).unwrap_or_default())
    }
    fn write(&self, m: &BTreeMap<String, String>) -> Result<()> {
        std::fs::write(&self.path, serde_json::to_string(m)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

impl Stash for FileStash {
    fn backend(&self) -> &'static str {
        "insecure-file"
    }
    fn get(&self, key: &str) -> Result<Option<SecretString>> {
        Ok(self.read()?.remove(key).map(SecretString::from))
    }
    fn set(&self, key: &str, value: &SecretString) -> Result<()> {
        let mut m = self.read()?;
        m.insert(key.to_string(), value.expose_secret().to_string());
        self.write(&m)
    }
    fn delete(&self, key: &str) -> Result<bool> {
        let mut m = self.read()?;
        let had = m.remove(key).is_some();
        self.write(&m)?;
        Ok(had)
    }
}
