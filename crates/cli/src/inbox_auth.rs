//! Session authentication for the localhost inbox: the token file, the challenge-response
//! ownership proof, and constant-time comparison.
//!
//! # Why the inbox needs a credential at all
//!
//! Binding 127.0.0.1 is not a security boundary. Every process on the machine can reach
//! the port, and so can any web page the user happens to visit: a cross-origin `<form>`
//! POST to `http://127.0.0.1:<port>/` is not blocked by CORS (the request is sent; only
//! the *response* is hidden, and the attacker does not need the response). Without a
//! credential, anything that can make an HTTP request can answer a task — which means it
//! can store a value of its choosing under a real key name and approve its own trust
//! gates. The session token closes that.
//!
//! # Two sessions: paste-scope for the agent's link, full-scope for the human's
//!
//! The agent is the one who tells the human "you need to paste OPENAI_API_KEY" — so the
//! most useful thing it can hand over is a link that works. But a link that can *approve*
//! ("yes, this project may use my Stripe key") must not sit in the agent's hands: an agent
//! manipulated by something in a repo could open it and approve its own request.
//!
//! So there are two tokens. The **paste-scope** token (`inbox.paste.token`) can answer
//! missing-key cards and human tasks — self-answering is useless to an attacker, who has no
//! real key to paste. It is what agent surfaces (MCP results, `need` output) carry, so the
//! human can click straight from the chat. The **full-scope** token (`inbox.token`) can also
//! approve; it travels only over channels a person triggers (the desktop notification,
//! `tokenstash open`, a terminal). A full-scope cookie is never downgraded by a later
//! paste-scope link, so one `tokenstash open` per browser makes every agent link fully
//! capable from then on. `inbox_links = "full"` in config opts into handing the full token to
//! agent surfaces on machines where that trade-off is wanted.
//!
//! # Why /verify is a challenge, not a token check
//!
//! Before the CLI reuses "something is listening on the inbox port", it has to know the
//! listener is *our* inbox for *this* `TOKENSTASH_HOME`. It must not find that out by
//! sending the token — a hostile squatter on the port would simply collect it. Instead the
//! CLI sends a fresh nonce and the server answers `HMAC-SHA256(token, nonce)`: only a
//! process that already holds the token can produce it, and the token never crosses the
//! wire. That is why `/verify` is the one route that does not require authentication.

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::path::PathBuf;
use subtle::ConstantTimeEq;
use tokenstash_core::fsutil;

/// Name of the session cookie set on the first tokened visit.
pub const COOKIE: &str = "tokenstash_inbox";

/// 32 bytes, hex-encoded to 64 characters.
const TOKEN_BYTES: usize = 32;
const TOKEN_CHARS: usize = TOKEN_BYTES * 2;

/// Longest `?c=` challenge `/verify` will answer. Bounds the work an unauthenticated
/// caller can ask for.
pub const MAX_CHALLENGE: usize = 128;

pub fn token_path() -> PathBuf {
    tokenstash_core::config::config_dir().join("inbox.token")
}

/// The paste-scope token file. Separate random bytes, not derived from the full token, so
/// holding one says nothing about the other.
pub fn paste_token_path() -> PathBuf {
    tokenstash_core::config::config_dir().join("inbox.paste.token")
}

/// What a presented credential is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Answer missing-key cards and human tasks. Cannot approve.
    Paste,
    /// Everything, including approvals.
    Full,
}

/// Both tokens, read or created together.
#[derive(Debug, Clone)]
pub struct Tokens {
    pub full: String,
    pub paste: String,
}

impl Tokens {
    pub fn ensure() -> Result<Self> {
        Ok(Self { full: ensure_token()?, paste: ensure_paste_token()? })
    }

    /// Classify a presented credential (cookie value, `?t=`, or CSRF field), constant-time.
    pub fn scope_of(&self, presented: &str) -> Option<Scope> {
        if ct_eq(presented, &self.full) {
            Some(Scope::Full)
        } else if ct_eq(presented, &self.paste) {
            Some(Scope::Paste)
        } else {
            None
        }
    }

    pub fn for_scope(&self, scope: Scope) -> &str {
        match scope {
            Scope::Full => &self.full,
            Scope::Paste => &self.paste,
        }
    }
}

/// The session token for this `TOKENSTASH_HOME`, creating it on first use.
///
/// The token is persisted rather than regenerated per inbox process on purpose: the inbox
/// exits after 30 idle minutes and respawns on demand, and a URL already handed to a human
/// (a desktop notification sitting in their tray) has to still work when they click it.
/// It lives at `$TOKENSTASH_HOME/inbox.token`, written 0600 and atomically, like every
/// other file in this project that holds a credential.
pub fn ensure_token() -> Result<String> {
    ensure_token_at(&token_path())
}

/// The paste-scope token, same lifecycle as [`ensure_token`].
pub fn ensure_paste_token() -> Result<String> {
    ensure_token_at(&paste_token_path())
}

fn ensure_token_at(path: &std::path::Path) -> Result<String> {
    let path = path.to_path_buf();
    if let Some(t) = read_token_at(&path) {
        return Ok(t);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // Two commands can race to create the token; the loser must adopt the winner's value,
    // not overwrite it, or URLs already printed stop working.
    fsutil::with_lock(&path, || {
        if let Some(t) = read_token_at(&path) {
            return Ok(t);
        }
        let mut bytes = [0u8; TOKEN_BYTES];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex(&bytes);
        fsutil::write_atomic_private(&path, &token)?;
        Ok(token)
    })
}

/// A token as already stored, or `None` if there is no well-formed one yet.
fn read_token_at(path: &std::path::Path) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim().to_string();
    (s.len() == TOKEN_CHARS && s.bytes().all(|b| b.is_ascii_hexdigit())).then_some(s)
}

/// The answer to a `/verify?c=<challenge>` ownership probe: `HMAC-SHA256(token, challenge)`,
/// hex. Keyed with the token's ASCII bytes, exactly as the token appears in the file and in
/// a `?t=` URL, so any client can reproduce it without knowing an encoding convention.
pub fn verify_response(token: &str, challenge: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(token.as_bytes()).expect("hmac accepts any key length");
    mac.update(challenge.as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// Compare two credentials without leaking, through timing, how long a prefix matched.
/// Lengths are compared normally: the token length is fixed and public, only the bytes are
/// secret.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// A fresh nonce for a `/verify` probe.
pub fn challenge() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex(&bytes)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// `TOKENSTASH_HOME` is process-global, so every test that sets it shares this lock.
#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_home(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("tokenstash-inbox-auth-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn token_file_is_private_stable_and_well_formed() {
        let _g = env_lock();
        let home = tmp_home("perms");
        std::env::set_var("TOKENSTASH_HOME", &home);

        let t = ensure_token().unwrap();
        assert_eq!(t.len(), 64, "32 random bytes, hex");
        assert!(t.bytes().all(|b| b.is_ascii_hexdigit()));

        // A second call adopts the stored token instead of minting a new one: URLs already
        // handed to a human must keep working.
        assert_eq!(ensure_token().unwrap(), t);
        assert_eq!(read_token_at(&token_path()).unwrap(), t);
        assert_eq!(std::fs::read_to_string(token_path()).unwrap(), t, "no trailing newline");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(token_path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the token file must not be readable by other users");
        }

        // Two homes never share a token: the proof is per-TOKENSTASH_HOME.
        let other = tmp_home("perms-other");
        std::env::set_var("TOKENSTASH_HOME", &other);
        assert_ne!(ensure_token().unwrap(), t);

        std::env::remove_var("TOKENSTASH_HOME");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn paste_and_full_tokens_are_distinct_and_classified_in_constant_time() {
        let _g = env_lock();
        let home = tmp_home("scopes");
        std::env::set_var("TOKENSTASH_HOME", &home);

        let t = Tokens::ensure().unwrap();
        assert_ne!(t.full, t.paste, "the paste token must not be derivable from the full one");
        assert_eq!(t.paste.len(), 64);
        assert_eq!(t.scope_of(&t.full), Some(Scope::Full));
        assert_eq!(t.scope_of(&t.paste), Some(Scope::Paste));
        assert_eq!(t.scope_of(""), None);
        assert_eq!(t.scope_of(&t.full[..63]), None);
        // Stable across calls: links already handed out keep working.
        let again = Tokens::ensure().unwrap();
        assert_eq!(again.full, t.full);
        assert_eq!(again.paste, t.paste);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(paste_token_path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        std::env::remove_var("TOKENSTASH_HOME");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn read_token_rejects_a_malformed_file() {
        let _g = env_lock();
        let home = tmp_home("malformed");
        std::env::set_var("TOKENSTASH_HOME", &home);

        for junk in ["", "   ", "not-hex-at-all", &"a".repeat(63), &"z".repeat(64)] {
            std::fs::write(token_path(), junk).unwrap();
            assert!(read_token_at(&token_path()).is_none(), "should reject {junk:?}");
        }
        // ...and a malformed file is replaced with a real token rather than trusted.
        let t = ensure_token().unwrap();
        assert_eq!(t.len(), 64);

        std::env::remove_var("TOKENSTASH_HOME");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn verify_response_is_hmac_and_binds_both_token_and_challenge() {
        // Known-answer vector: HMAC-SHA256(key="key", msg="The quick brown fox jumps over the lazy dog").
        assert_eq!(
            verify_response("key", "The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        let token = "a".repeat(64);
        let other = "b".repeat(64);
        assert_eq!(verify_response(&token, "n1").len(), 64);
        // A different challenge gives a different answer, so a recorded reply proves nothing.
        assert_ne!(verify_response(&token, "n1"), verify_response(&token, "n2"));
        // A different token gives a different answer, so another TOKENSTASH_HOME's inbox
        // squatting the port fails the proof.
        assert_ne!(verify_response(&token, "n1"), verify_response(&other, "n1"));
        // Deterministic: the prober can recompute it.
        assert_eq!(verify_response(&token, "n1"), verify_response(&token, "n1"));
    }

    #[test]
    fn ct_eq_matches_string_equality() {
        let token = "0123456789abcdef".repeat(4);
        assert!(ct_eq(&token, &token.clone()));
        assert!(!ct_eq(&token, &token[..63]), "a prefix is not a match");
        assert!(!ct_eq(&token, &format!("{token}0")), "an extension is not a match");
        assert!(!ct_eq(&token, &token.replacen('0', "1", 1)), "one differing byte is not a match");
        assert!(!ct_eq(&token, ""));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn challenges_do_not_repeat() {
        let a = challenge();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, challenge());
    }
}
