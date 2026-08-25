//! Trust model (tokenstash.md §3.5): a stash miss is self-gating (a human is asked).
//! A stash hit is silent unless the project is outside every trust root or the key is sensitive.

use crate::{Config, Db};
use anyhow::Result;
use std::path::Path;

/// Both sides are canonicalized: a project path containing `..` or a symlink that
/// resolves outside a root must not be classified as trusted.
pub fn inside_roots(project: &Path, cfg: &Config) -> bool {
    let project = match project.canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    cfg.trust_roots.iter().any(|r| match r.canonicalize() {
        Ok(r) => project.starts_with(&r),
        Err(_) => false,
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
    // Key approvals by the resolved path; an unresolvable path is never approved.
    let Ok(project) = project.canonicalize() else {
        return Ok(Gate::NeedsApproval { reason: GateReason::OutsideTrustRoots });
    };
    let project = project.as_path();
    let pid = project.to_string_lossy();
    if sensitive && !db.is_approved_exact(&pid, name)? {
        return Ok(Gate::NeedsApproval { reason: GateReason::Sensitive });
    }
    if !inside_roots(project, cfg) && !db.is_approved(&pid, "*")? {
        return Ok(Gate::NeedsApproval { reason: GateReason::OutsideTrustRoots });
    }
    Ok(Gate::Open)
}
