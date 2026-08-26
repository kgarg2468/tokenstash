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

/// One cheap authenticated request. Never logs the value. Network failure → Unknown (accept).
pub fn liveness(check: &Check, value: &SecretString) -> Liveness {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(8))
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
        Ok(_) => Liveness::Ok,
        Err(ureq::Error::Status(code, _)) => {
            if code == 401 || code == 403 || check.reject_status.contains(&code) {
                Liveness::Rejected(code)
            } else if code == 429 || code >= 500 {
                // The provider did not evaluate the key (rate-limited, down): no verdict.
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
    for p in crate::registry::all() {
        if let Some(pat) = &p.pattern {
            if regex::Regex::new(pat).map(|re| re.is_match(t)).unwrap_or(false) {
                return true;
            }
        }
    }
    let single_token = !t.chars().any(char::is_whitespace);
    let long = t.chars().count() >= 24;
    let has_digit = t.chars().any(|c| c.is_ascii_digit());
    let has_alpha = t.chars().any(|c| c.is_ascii_alphabetic());
    let url_with_creds = t.contains("://") && t.contains('@');
    (single_token && long && has_digit && has_alpha) || url_with_creds
}
