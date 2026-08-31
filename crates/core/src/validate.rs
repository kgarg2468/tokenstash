//! Pattern + liveness validation at paste time, so a typo fails now, not 20 minutes later.

use crate::registry::Check;
use anyhow::Result;
use secrecy::{ExposeSecret, SecretString};
use std::time::Duration;

pub fn matches_pattern(pattern: &str, value: &SecretString) -> Result<bool> {
    let re = regex::Regex::new(pattern)?;
    Ok(re.is_match(value.expose_secret()))
}

#[derive(Debug, Clone, PartialEq)]
pub enum Liveness {
    Ok,
    Rejected(u16),
    Unknown(String),
}

impl Liveness {
    /// The provider said "slow down": the next probe must wait longer than after a mere outage.
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Liveness::Unknown(s) if s == "HTTP 429")
    }
    /// The provider evaluated the key and found it live but not permitted on the probe
    /// endpoint (a restricted key). A verdict that will not change soon.
    pub fn is_forbidden(&self) -> bool {
        matches!(self, Liveness::Unknown(s) if s == "HTTP 403")
    }
}

/// Timeout for a human-initiated probe (paste, `check`, import).
pub const TIMEOUT_HUMAN: Duration = Duration::from_secs(8);
/// Timeout for a probe on the agent's hot path (verify-on-use in `need`).
pub const TIMEOUT_AT_USE: Duration = Duration::from_secs(4);

/// One cheap authenticated request. Never logs the value. Network failure → Unknown (accept).
///
/// Verdicts: 401 (or a status the registry lists in `reject_status`) → Rejected. 403 is
/// "authenticated but not permitted" — a restricted Stripe/SendGrid key answers 403 on an
/// endpoint outside its scope and is perfectly alive — so it is Unknown, never Rejected.
/// 429/5xx: the provider did not evaluate the key → Unknown. Redirects are never followed:
/// `ureq` would forward custom auth headers (xi-api-key, X-Subscription-Token) to whatever
/// origin the 3xx names, and strips Authorization so a redirected bearer probe would 401 on
/// a live key. A 3xx is therefore Unknown too.
pub fn liveness(check: &Check, value: &SecretString, timeout: Duration) -> Liveness {
    // The registry is compiled in and a test asserts every check URL is https, but this is
    // the line the secret actually crosses, so it asserts it too: a plain-http probe would
    // put the key on the wire in clear. Cheap, and it holds for whatever edits the file.
    if !url_is_safe_for_a_secret(&check.url) {
        return Liveness::Unknown("provider check URL is not https; refusing to send the key".into());
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(0)
        .user_agent("tokenstash-liveness/0.1")
        .build();
    let v = value.expose_secret();
    let mut url = check.url.clone();
    let mut req = match check.method.to_ascii_uppercase().as_str() {
        "POST" => agent.post(&url),
        _ => agent.get(&url),
    };
    match check.auth.as_str() {
        "bearer" => req = req.set("Authorization", &format!("Bearer {v}")),
        "basic-user" => {
            use base64::Engine;
            let b = base64::engine::general_purpose::STANDARD.encode(format!("{v}:"));
            req = req.set("Authorization", &format!("Basic {b}"));
        }
        a if a.starts_with("header:") => req = req.set(&a["header:".len()..], v),
        a if a.starts_with("prefix:") => req = req.set("Authorization", &format!("{} {v}", &a["prefix:".len()..])),
        a if a.starts_with("query:") => {
            let p = &a["query:".len()..];
            let sep = if url.contains('?') { '&' } else { '?' };
            url = format!("{url}{sep}{p}={v}");
            req = match check.method.to_ascii_uppercase().as_str() {
                "POST" => agent.post(&url),
                _ => agent.get(&url),
            };
        }
        _ => {}
    }
    for (k, val) in &check.headers {
        req = req.set(k, val);
    }
    let resp = if check.method.eq_ignore_ascii_case("POST") { req.send_string("{}") } else { req.call() };
    match resp {
        // With redirects off, ureq hands a 3xx back as a plain response.
        Ok(r) if (300..400).contains(&r.status()) => Liveness::Unknown(format!("HTTP {}", r.status())),
        Ok(_) => Liveness::Ok,
        Err(ureq::Error::Status(code, _)) => {
            if code == 401 || check.reject_status.contains(&code) {
                Liveness::Rejected(code)
            } else if code == 403 || code == 429 || code >= 500 {
                // The provider did not evaluate the key (rate-limited, down, redirecting)
                // or evaluated it and found it live but under-scoped (403): no verdict.
                // Treating this as "accepted" would let an outage record a genuine dead-key
                // report as a false report and suppress it for the whole cooldown.
                Liveness::Unknown(format!("HTTP {code}"))
            } else {
                // 400/404 etc. usually mean the key was accepted but the probe was imperfect.
                Liveness::Ok
            }
        }
        Err(e) => Liveness::Unknown(redact_err(&e.to_string(), v)),
    }
}

/// https anywhere, or plain http to loopback (what the tests probe, and what a local
/// provider stub would be). Anything else would put the key on the wire in clear.
fn url_is_safe_for_a_secret(url: &str) -> bool {
    let l = url.to_ascii_lowercase();
    if l.starts_with("https://") {
        return true;
    }
    let Some(rest) = l.strip_prefix("http://") else { return false };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("").rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| rest.split(['/', '?', '#']).next().unwrap_or("").to_string());
    matches!(host.trim_start_matches('[').trim_end_matches(']'), "127.0.0.1" | "::1" | "localhost")
}

fn redact_err(msg: &str, v: &str) -> String {
    crate::redact::Redactor::new().with(&SecretString::from(v.to_string())).redact(msg)
}

/// Heuristic used to refuse a free-text human answer that is actually a credential. Matches
/// any registry key pattern, or a single long token with no whitespace (API keys, JWTs,
/// connection strings). Free-text answers are returned to the agent; secrets must go
/// through the secret flow where they are never emitted.
pub fn looks_like_secret(text: &str) -> bool {
    let t = text.trim();
    if t.is_empty() {
        return false;
    }
    // Registry patterns are anchored (`^sk-`), so they are tried against each token as well
    // as the whole answer: "the key is sk-live-..." is the shape a human actually types.
    let tokens: Vec<&str> = t.split_whitespace().collect();
    for p in crate::registry::all() {
        if let Some(pat) = &p.pattern {
            if let Ok(re) = regex::Regex::new(pat) {
                if re.is_match(t) || tokens.iter().any(|tok| re.is_match(tok)) {
                    return true;
                }
            }
        }
    }
    let long = |s: &str| s.chars().count() >= 24;
    let mixed = |s: &str| s.chars().any(|c| c.is_ascii_digit()) && s.chars().any(|c| c.is_ascii_alphabetic());
    // A long opaque token buried in a sentence: "the staging password is 8f3c...".
    if tokens.iter().any(|tok| long(tok) && mixed(tok)) {
        return true;
    }
    let url_with_creds = t.contains("://") && t.contains('@');
    if url_with_creds {
        return true;
    }
    // A single long token with no digits at all is still a credential shape — a wordless
    // passphrase ("correcthorsebatterystaple") is exactly what a human types when asked for
    // one. Plain URLs and paths are the answers that legitimately look like this.
    let single_token = tokens.len() == 1;
    let is_url_or_path = ["http://", "https://", "/", "./", "../", "~/"].iter().any(|p| t.starts_with(p));
    single_token && long(t) && !is_url_or_path
}
