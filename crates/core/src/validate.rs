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
            if code == 401 || code == 403 {
                Liveness::Rejected(code)
            } else {
                // 400/404/429 etc. usually mean the key was accepted but the probe was imperfect.
                Liveness::Ok
            }
        }
        Err(e) => Liveness::Unknown(redact_err(&e.to_string(), v)),
    }
}

fn redact_err(msg: &str, v: &str) -> String {
    crate::redact::Redactor::new().with(&SecretString::from(v.to_string())).redact(msg)
}
