//! Trust model (tokenstash.md §3.5): a stash miss is self-gating (a human is asked).
//! A stash hit is silent unless the project is outside every trust root or the key is sensitive.

use crate::{Config, Db};
use anyhow::Result;
use std::path::Path;

pub fn inside_roots(project: &Path, cfg: &Config) -> bool {
    cfg.trust_roots.iter().any(|r| {
        let r = r.canonicalize().unwrap_or_else(|_| r.clone());
        project.starts_with(&r)
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum Gate {
    /// Inject silently.
    Open,
    /// Needs a one-time approval for this project.
    NeedsApproval { reason: GateReason },
}

#[derive(Debug, Clone, PartialEq)]
pub enum GateReason {
    OutsideTrustRoots,
    Sensitive,
}

pub fn gate(db: &Db, cfg: &Config, project: &Path, name: &str, sensitive: bool) -> Result<Gate> {
    let pid = project.to_string_lossy();
    if sensitive && !db.is_approved(&pid, name)? {
        return Ok(Gate::NeedsApproval { reason: GateReason::Sensitive });
    }
    if !inside_roots(project, cfg) && !db.is_approved(&pid, "*")? {
        return Ok(Gate::NeedsApproval { reason: GateReason::OutsideTrustRoots });
    }
    Ok(Gate::Open)
}
