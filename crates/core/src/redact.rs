//! Last line of defense: scrub any known secret value out of text bound for a human or a model.

use secrecy::{ExposeSecret, SecretString};

/// Values shorter than this are only redacted as whole tokens (surrounded by
/// non-alphanumerics): replacing every "ab" inside other words would garble output.
/// Defense in depth only — `tasks::MIN_SECRET_CHARS` keeps such values out of the stash
/// in the first place, so nothing this short is ever a stored secret.
const SHORT: usize = 4;

pub struct Redactor {
    values: Vec<String>,
}

impl Redactor {
    pub fn new() -> Self {
        Self { values: vec![] }
    }
    pub fn with(mut self, v: &SecretString) -> Self {
        self.add(v);
        self
    }
    pub fn add(&mut self, v: &SecretString) {
        let s = v.expose_secret();
        if !s.is_empty() {
            self.values.push(s.to_string());
        }
    }
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for v in &self.values {
            if !out.contains(v.as_str()) {
                continue;
            }
            if v.chars().count() >= SHORT {
                out = out.replace(v.as_str(), "[redacted]");
            } else {
                out = redact_whole_token(&out, v);
            }
        }
        out
    }
}

/// Replace `v` only where it is not glued to other alphanumerics.
fn redact_whole_token(text: &str, v: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(v) {
        let before_ok = rest[..i].chars().next_back().map(|c| !c.is_alphanumeric()).unwrap_or(true);
        let after_ok = rest[i + v.len()..].chars().next().map(|c| !c.is_alphanumeric()).unwrap_or(true);
        out.push_str(&rest[..i]);
        if before_ok && after_ok {
            out.push_str("[redacted]");
        } else {
            out.push_str(v);
        }
        rest = &rest[i + v.len()..];
    }
    out.push_str(rest);
    out
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

/// Mask for display: first 3 + last 2 characters, never more. Char-based so multibyte
/// values cannot panic on a byte boundary.
pub fn mask(v: &SecretString) -> String {
    let s = v.expose_secret();
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        return "••••".into();
    }
    let first: String = chars[..3].iter().collect();
    let last: String = chars[chars.len() - 2..].iter().collect();
    format!("{first}…{last}")
}
