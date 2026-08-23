//! Private, atomic file writes. Used for anything that holds a secret value.

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Write `contents` to `path` such that:
/// - the file is 0600 from the first byte (created with that mode, O_EXCL temp file);
/// - a pre-existing symlink at `path` is refused, never written through;
/// - the write is atomic: on any failure the previous file is untouched;
/// - the temp file is never left behind.
pub fn write_atomic_private(path: &Path, contents: &str) -> Result<()> {
    if let Ok(md) = fs::symlink_metadata(path) {
        if md.file_type().is_symlink() {
            bail!("{} is a symlink; refusing to write a secret through it", path.display());
        }
        if !md.is_file() {
            bail!("{} exists and is not a regular file", path.display());
        }
    }
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".into());
    let tmp = dir.join(format!(".{name}.tokenstash-{}.tmp", std::process::id()));
    let _guard = RemoveOnDrop(tmp.clone());

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true); // O_EXCL: fails if anything (incl. a symlink) is there
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // belt and braces for filesystems that ignore mode at create
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Cross-process mutual exclusion for read-modify-write of a private file. A sibling
/// `<name>.lock` is created with O_EXCL; contenders retry for up to ~5s. A lock older than
/// 30s is treated as abandoned (crashed holder) and reclaimed.
pub fn with_lock<T>(path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let lock = path.with_extension("lock");
    let start = std::time::Instant::now();
    loop {
        match fs::OpenOptions::new().write(true).create_new(true).open(&lock) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let stale = fs::metadata(&lock).and_then(|m| m.modified()).map(|t| t.elapsed().map(|d| d.as_secs() > 30).unwrap_or(false)).unwrap_or(true);
                if stale {
                    let _ = fs::remove_file(&lock);
                    continue;
                }
                if start.elapsed().as_secs() > 5 {
                    bail!("{} is locked by another tokenstash process", path.display());
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(e) => return Err(e).with_context(|| format!("creating lock {}", lock.display())),
        }
    }
    let _guard = RemoveOnDrop(lock);
    f()
}

struct RemoveOnDrop(std::path::PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
