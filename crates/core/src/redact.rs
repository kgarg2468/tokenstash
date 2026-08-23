//! Last line of defense: scrub any known secret value out of text bound for a human or a model.

use secrecy::{ExposeSecret, SecretString};

pub struct Redactor {
    values: Vec<String>,
}

impl Redactor {
    pub fn new() -> Self {
        Self { values: vec![] }
    }
    pub fn with(mut self, v: &SecretString) -> Self {
        let s = v.expose_secret();
        if s.len() >= 4 {
            self.values.push(s.to_string());
        }
        self
    }
    pub fn add(&mut self, v: &SecretString) {
        let s = v.expose_secret();
        if s.len() >= 4 {
            self.values.push(s.to_string());
        }
    }
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for v in &self.values {
            if out.contains(v.as_str()) {
                out = out.replace(v.as_str(), "[redacted]");
            }
        }
        out
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

/// Mask for display: first 3 + last 2 chars, never more.
pub fn mask(v: &SecretString) -> String {
    let s = v.expose_secret();
    if s.len() <= 8 {
        return "••••".into();
    }
    format!("{}…{}", &s[..3], &s[s.len() - 2..])
}
