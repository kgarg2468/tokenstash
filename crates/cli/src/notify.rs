//! Desktop notification + make sure the inbox is up. Best effort; never fatal.

use crate::inbox_auth;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use tokenstash_core::Config;

/// What is actually on the inbox port.
///
/// "Something accepted a TCP connection" is not the same as "our inbox is running", and the
/// difference matters: we are about to tell a human to paste an API key into whatever is
/// there. `Ours` is only ever returned after the listener answers a fresh challenge with
/// `HMAC(token, nonce)` — a proof it already holds this `TOKENSTASH_HOME`'s token. The token
/// itself is never sent, so a squatter on the port learns nothing from being probed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbox {
    /// Verified: this is our inbox for this TOKENSTASH_HOME.
    Ours,
    /// Something is listening but failed the ownership proof.
    Foreign,
    /// Nothing is listening.
    Down,
}

const CONNECT_TIMEOUT: Duration = Duration::from_millis(400);
const IO_TIMEOUT: Duration = Duration::from_millis(1500);
/// A hostile listener must not be able to stream at us forever.
const MAX_REPLY: u64 = 64 * 1024;

fn addr(cfg: &Config) -> SocketAddr {
    ([127, 0, 0, 1], cfg.inbox_port).into()
}

pub fn inbox_state(cfg: &Config) -> Inbox {
    let Ok(token) = inbox_auth::ensure_token() else { return Inbox::Down };
    probe(&addr(cfg), &token)
}

fn probe(addr: &SocketAddr, token: &str) -> Inbox {
    let Ok(mut s) = TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) else { return Inbox::Down };
    let nonce = inbox_auth::challenge();
    match challenge(&mut s, addr, &nonce) {
        Some(body) if inbox_auth::ct_eq(body.trim(), &inbox_auth::verify_response(token, &nonce)) => Inbox::Ours,
        _ => Inbox::Foreign,
    }
}

/// One `GET /verify?c=<nonce>` over a raw socket, returning the response body. Hand-rolled
/// rather than pulling in an HTTP client: one request, one connection, no redirects.
fn challenge(s: &mut TcpStream, addr: &SocketAddr, nonce: &str) -> Option<String> {
    s.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
    s.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
    write!(s, "GET /verify?c={nonce} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").ok()?;
    s.flush().ok()?;
    let mut buf = Vec::new();
    s.take(MAX_REPLY).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8(buf).ok()?;
    let (head, body) = text.split_once("\r\n\r\n")?;
    head.starts_with("HTTP/1.1 200").then(|| body.to_string())
}

/// Spawn `tokenstash inbox` detached unless our own, verified inbox is already up.
pub fn ensure_inbox(cfg: &Config) {
    match inbox_state(cfg) {
        Inbox::Ours => return,
        Inbox::Foreign => {
            // Do not spawn (the bind would fail) and, more importantly, do not send a human
            // to a URL owned by someone else. Nothing secret was disclosed getting here.
            eprintln!(
                "tokenstash: port {} is held by another process — it failed the inbox ownership check, so nothing was sent to it.\n\
                 Stop that process or set inbox_port in {}.",
                cfg.inbox_port,
                tokenstash_core::config::config_path().display()
            );
            return;
        }
        Inbox::Down => {}
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
        if inbox_state(cfg) == Inbox::Ours {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("tokenstash: the inbox did not come up on port {}", cfg.inbox_port);
}

/// Human-readable inbox status for `doctor`.
pub fn inbox_status(cfg: &Config) -> &'static str {
    match inbox_state(cfg) {
        Inbox::Ours => "running (ownership verified)",
        Inbox::Foreign => "PORT HELD BY ANOTHER PROCESS — it failed the ownership check",
        Inbox::Down => "not running (starts on demand)",
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
