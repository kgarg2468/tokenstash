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
    let mut c = std::process::Command::new(exe);
    c.arg("inbox").env("TOKENSTASH_INBOX_TOKEN", inbox_token()).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        c.process_group(0);
    }
    let _ = c.spawn();
    for _ in 0..20 {
        if inbox_running(cfg) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
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
