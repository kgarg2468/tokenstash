//! Desktop notification + make sure the inbox is up. Best effort; never fatal.

use std::net::TcpStream;
use std::time::Duration;
use tokenstash_core::Config;

pub fn inbox_running(cfg: &Config) -> bool {
    TcpStream::connect_timeout(&format!("127.0.0.1:{}", cfg.inbox_port).parse().unwrap(), Duration::from_millis(300)).is_ok()
}

/// Spawn `tokenstash inbox` detached if nothing is listening.
pub fn ensure_inbox(cfg: &Config) {
    if inbox_running(cfg) {
        return;
    }
    let Ok(exe) = std::env::current_exe() else { return };
    let mut c = std::process::Command::new(exe);
    c.arg("inbox").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
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
