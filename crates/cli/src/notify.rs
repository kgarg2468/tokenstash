//! Desktop notification + make sure the inbox is up. Best effort; never fatal.

use std::net::TcpStream;
use std::time::Duration;
use tokenstash_core::Config;

pub fn inbox_running(cfg: &Config) -> bool {
    TcpStream::connect_timeout(&format!("127.0.0.1:{}", cfg.inbox_port).parse().unwrap(), Duration::from_millis(300)).is_ok()
}

/// Shared secret for the localhost inbox.
///
/// The inbox can approve tasks and store values, so a bare `POST http://127.0.0.1:<port>/t/<id>`
/// must not be honored from anywhere (a hostile page CSRFing the loopback, or an agent
/// replaying a URL it saw in its own transcript). Every route except `/health` requires this
/// token, and it is never written to stdout/stderr/MCP results — it travels only inside
/// desktop-notification deep links. Honest scope: another process running as the same user
/// could read the token file; that is outside what a local-first CLI can prevent.
pub fn inbox_token() -> String {
    let path = tokenstash_core::config::config_dir().join("inbox.token");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim();
        if s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            return s.to_string();
        }
    }
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    let tok: String = b.iter().map(|x| format!("{x:02x}")).collect();
    let dir = tokenstash_core::config::config_dir();
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        if path.exists() {
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
    let _ = std::fs::write(&path, &tok);
    tok
}

/// Spawn `tokenstash inbox` detached if nothing is listening.
pub fn ensure_inbox(cfg: &Config) {
    if inbox_running(cfg) {
        return;
    }
    let Ok(exe) = std::env::current_exe() else { return };
    let token = inbox_token();
    let mut c = std::process::Command::new(exe);
    c.arg("inbox").env("TOKENSTASH_INBOX_TOKEN", token).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        c.process_group(0);
    }
    let _ = c.spawn();
    for _ in 0..20 {
        if port_knows_token(cfg) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Minimal one-shot HTTP GET over raw TCP; returns the response body, or None.
fn http_get(port: u16, path_qs: &str) -> Option<String> {
    use std::io::{Read, Write};
    let mut s = TcpStream::connect_timeout(&format!("127.0.0.1:{port}").parse().ok()?, Duration::from_millis(500)).ok()?;
    write!(s, "GET {path_qs} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    buf.split_once("\r\n\r\n").map(|(_, body)| body.to_string())
}

/// True when whatever listens on the inbox port proves it knows the session token —
/// i.e., it is our inbox and not a port squatter waiting to capture deep links.
/// Challenge–response: the raw token never touches the wire on this path.
fn port_knows_token(cfg: &Config) -> bool {
    use sha2::Digest;
    let token = inbox_token();
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    let challenge: String = b.iter().map(|x| format!("{x:02x}")).collect();
    let expected = format!("{:x}", sha2::Sha256::digest(format!("{token}:{challenge}")));
    http_get(cfg.inbox_port, &format!("/verify?c={challenge}")).map(|body| body.trim() == expected).unwrap_or(false)
}

/// Deep link for humans (desktop notification / `tokenstash open`), only when the
/// listener on our port has proven it is ours. None means: don't hand out links.
pub fn verified_inbox_link(cfg: &Config, task_id: Option<&str>) -> Option<String> {
    if !port_knows_token(cfg) {
        return None;
    }
    Some(crate::util::inbox_link(cfg, task_id))
}

pub fn desktop(cfg: &Config, title: &str, body: &str, url: &str) {
    if !cfg.notifications {
        return;
    }
    let _ = notify_rust::Notification::new()
        .appname("tokenstash")
        .summary(title)
        .body(&format!("{body}\n{url}"))
        .timeout(notify_rust::Timeout::Milliseconds(15000))
        .show();
}
