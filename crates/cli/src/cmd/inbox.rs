//! Localhost inbox: the human surface. One click from the notification to the vendor's page,
//! paste, submit. Binds 127.0.0.1 only. Exits after 30 idle minutes with no open tasks.
//!
//! Loopback is not authentication — see `crate::inbox_auth` for the threat model. Every route
//! except `/verify` requires the session token: presented as `?t=` on the first visit, then
//! held as an `HttpOnly; SameSite=Strict` cookie. POSTs additionally carry it in a hidden form
//! field (double submit), so a cross-site form post cannot ride the cookie into an answer.

use crate::inbox_auth;
use crate::util::App;
use anyhow::Result;
use clap::Args;
use secrecy::SecretString;
use std::collections::HashMap;
use std::io::Read;
use std::time::{Duration, Instant};
use tiny_http::{Header, Request, Response, Server};
use tokenstash_core::db::{Task, TaskKind, TaskStatus};
use tokenstash_core::tasks::{self, AnswerResult};

#[derive(Args)]
pub struct InboxArgs {
    #[arg(long)]
    pub port: Option<u16>,
    /// Never auto-exit.
    #[arg(long)]
    pub keep: bool,
}

const IDLE_EXIT: Duration = Duration::from_secs(30 * 60);

/// Cap on a form post. Answers are pasted API keys, not uploads.
const MAX_BODY: u64 = 64 * 1024;

pub fn serve(a: InboxArgs) -> Result<i32> {
    let app = App::open()?;
    let port = a.port.unwrap_or(app.cfg.inbox_port);
    // Minted here on the first ever start and reused afterwards, so a notification the human
    // has not clicked yet still opens after the inbox has idled out and been respawned.
    let token = inbox_auth::ensure_token()?;
    let server = match Server::http(format!("127.0.0.1:{port}")) {
        Ok(s) => s,
        Err(_) => { eprintln!("inbox already running on {port}"); return Ok(0); }
    };
    eprintln!("tokenstash inbox → http://127.0.0.1:{port}/");
    let mut last_activity = Instant::now();
    loop {
        match server.recv_timeout(Duration::from_secs(1)) {
            Ok(Some(req)) => {
                last_activity = Instant::now();
                if let Err(e) = handle(&app, req, &token) {
                    eprintln!("inbox: {e:#}");
                }
            }
            Ok(None) => {
                if !a.keep && last_activity.elapsed() > IDLE_EXIT {
                    let _ = app.db.expire_overdue();
                    if app.db.list_tasks(None, true).map(|v| v.is_empty()).unwrap_or(true) {
                        return Ok(0);
                    }
                    last_activity = Instant::now();
                }
            }
            Err(e) => { eprintln!("inbox: {e}"); return Ok(1); }
        }
    }
}

fn handle(app: &App, mut req: Request, token: &str) -> Result<()> {
    let url = req.url().to_string();
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (url.clone(), String::new()),
    };
    let q = parse_form(&query);
    let method = req.method().as_str().to_string();

    // The one unauthenticated route, and deliberately ahead of every other check: it is how a
    // CLI that has not yet decided to trust this listener asks "are you the tokenstash inbox
    // for my TOKENSTASH_HOME?" without handing over the token to find out. We answer a fresh
    // nonce with HMAC(token, nonce); a process squatting the port cannot.
    if path == "/verify" {
        return match q.get("c") {
            Some(c) if !c.is_empty() && c.len() <= inbox_auth::MAX_CHALLENGE => {
                respond(req, 200, "text/plain", inbox_auth::verify_response(token, c))
            }
            _ => not_found(req),
        };
    }

    // Defence in depth against DNS rebinding: a hostname that resolves to 127.0.0.1 carries
    // the attacker's origin (so none of our cookies), but there is no reason to serve it.
    if !host_is_loopback(&req) {
        return not_found(req);
    }

    let cookie_ok = cookie(&req, inbox_auth::COOKIE).map(|c| inbox_auth::ct_eq(&c, token)).unwrap_or(false);
    // Read one byte past the limit so "exactly at the limit" and "too long" are
    // distinguishable. Truncating instead would be worse than refusing: the CSRF field sits at
    // the front of the body, so a cut-off form still authenticates, and parse_form would hand
    // a half-copied API key or note to answer_secret as though the human had typed it.
    let mut raw = Vec::new();
    if method == "POST" {
        req.as_reader().take(MAX_BODY + 1).read_to_end(&mut raw)?;
    }
    let oversized = raw.len() as u64 > MAX_BODY;
    let body = String::from_utf8_lossy(&raw);
    let form = if method == "POST" { parse_form(&body) } else { HashMap::new() };

    // GET: the cookie alone (SameSite=Strict stops a foreign page from making the browser
    // send it). POST: the cookie AND a matching hidden field — double submit, so even a
    // bypassed or unsupported SameSite cannot turn a cross-site form post into an answer.
    let authed = match method.as_str() {
        "POST" => cookie_ok && form.get("t").map(|t| inbox_auth::ct_eq(t, token)).unwrap_or(false),
        _ => cookie_ok,
    };
    if !authed {
        // First visit: the human clicked a `?t=<token>` URL from the notification or from
        // `tokenstash open`. Swap it for a cookie and bounce to a clean path so the token
        // stops appearing in the address bar, in history, and in any Referer we might send.
        if method == "GET" {
            if let Some(t) = q.get("t") {
                if inbox_auth::ct_eq(t, token) {
                    let rest: Vec<&str> = query.split('&').filter(|kv| !kv.is_empty() && !kv.starts_with("t=")).collect();
                    let dest = if rest.is_empty() { path.clone() } else { format!("{path}?{}", rest.join("&")) };
                    return redirect_authed(req, &dest, token);
                }
            }
        }
        return not_found(req);
    }

    // Checked after authentication so an unauthenticated caller still learns nothing (it gets
    // the same bare 404 as everything else), and before any task lookup so nothing is stored.
    if oversized {
        return respond(req, 413, "text/plain", "answer too large; nothing was stored".into());
    }

    app.db.expire_overdue()?;

    if path == "/health" {
        return respond(req, 200, "text/plain", "ok".into());
    }
    if path == "/api/tasks" {
        let list = app.db.list_tasks(None, true)?;
        return respond(req, 200, "application/json", serde_json::to_string(&list)?);
    }
    if path == "/" {
        let list = app.db.list_tasks(None, true)?;
        let flash = q.get("m").cloned();
        return respond(req, 200, "text/html; charset=utf-8", page_index(&list, flash.as_deref()));
    }
    if let Some(id) = path.strip_prefix("/t/") {
        let id = id.trim_end_matches('/').to_string();
        let Some(task) = app.db.find_task(&id)? else { return respond(req, 404, "text/plain", "no such task".into()) };
        if method == "GET" {
            return respond(req, 200, "text/html; charset=utf-8", page_task(&task, None, token));
        }
        if method == "POST" {
            let action = form.get("action").cloned().unwrap_or_default();
            let ctx = app.ctx();
            let msg: Result<String> = (|| {
                match (task.kind.clone(), action.as_str()) {
                    (_, "deny") => { tasks::deny(&ctx, &task, form.get("note").map(|s| s.as_str()))?; Ok(format!("Denied {}", task.title)) }
                    (TaskKind::Secret, _) => {
                        let v = form.get("value").cloned().unwrap_or_default();
                        let v = v.trim().to_string();
                        if v.is_empty() { anyhow::bail!("empty value"); }
                        let skip = form.contains_key("skip_check");
                        match tasks::answer_secret(&ctx, &task, SecretString::from(v), skip)? {
                            AnswerResult::Stored { injected_to, .. } => Ok(format!("Stored {} and wrote it to {}", task.name.clone().unwrap_or_default(), injected_to.map(|p| p.display().to_string()).unwrap_or_else(|| "the stash".into()))),
                            _ => Ok("stored".into()),
                        }
                    }
                    (TaskKind::Approval, _) => {
                        match tasks::answer_approval(&ctx, &task, action == "allow")? {
                            AnswerResult::Approved { injected } => Ok(format!("Approved; injected {}", if injected.is_empty() { "nothing new".into() } else { injected.join(", ") })),
                            _ => Ok("Denied".into()),
                        }
                    }
                    (TaskKind::Human, _) => { tasks::answer_human(&ctx, &task, form.get("note").map(|s| s.as_str()).filter(|s| !s.is_empty()))?; Ok(format!("Done: {}", task.title)) }
                }
            })();
            return match msg {
                Ok(m) => redirect(req, &format!("/?m={}", urlencoding::encode(&m))),
                Err(e) => respond(req, 200, "text/html; charset=utf-8", page_task(&task, Some(&format!("{e:#}")), token)),
            };
        }
    }
    not_found(req)
}

/// Anything the caller is not authorised for looks like nothing at all: bare 404, empty body.
/// A local process or a foreign page probing the port learns neither that an inbox is here nor
/// that a given task id exists.
fn not_found(req: Request) -> Result<()> {
    let r = Response::from_string("")
        .with_status_code(404)
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap());
    req.respond(r)?;
    Ok(())
}

fn header<'a>(req: &'a Request, name: &'static str) -> Option<&'a str> {
    req.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str())
}

fn cookie(req: &Request, name: &'static str) -> Option<String> {
    header(req, "Cookie")?.split(';').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k.trim() == name).then(|| v.trim().to_string())
    })
}

fn host_is_loopback(req: &Request) -> bool {
    let Some(v) = header(req, "Host") else { return false };
    let host = match v.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(), // [::1]:7433
        None => v.split(':').next().unwrap_or_default(),          // 127.0.0.1:7433
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn respond(req: Request, code: u16, ctype: &str, body: String) -> Result<()> {
    let r = Response::from_string(body)
        .with_status_code(code)
        .with_header(Header::from_bytes("Content-Type", ctype).unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
        .with_header(Header::from_bytes("X-Frame-Options", "DENY").unwrap());
    req.respond(r)?;
    Ok(())
}

/// 303 that also installs the session cookie. No `Secure` attribute: this is plain HTTP on the
/// loopback interface and `Secure` would make the browser drop the cookie outright. No
/// `Max-Age` either — it dies with the browser session.
fn redirect_authed(req: Request, to: &str, token: &str) -> Result<()> {
    let set_cookie = format!("{}={token}; Path=/; HttpOnly; SameSite=Strict", inbox_auth::COOKIE);
    let r = Response::from_string("")
        .with_status_code(303)
        .with_header(Header::from_bytes("Location", to).unwrap())
        .with_header(Header::from_bytes("Set-Cookie", set_cookie.as_str()).unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap());
    req.respond(r)?;
    Ok(())
}

fn redirect(req: Request, to: &str) -> Result<()> {
    let r = Response::from_string("").with_status_code(303).with_header(Header::from_bytes("Location", to).unwrap());
    req.respond(r)?;
    Ok(())
}

fn parse_form(s: &str) -> HashMap<String, String> {
    s.split('&')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            let dec = |x: &str| urlencoding::decode(&x.replace('+', " ")).map(|c| c.into_owned()).unwrap_or_default();
            Some((dec(k), dec(v)))
        })
        .collect()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

const CSS: &str = r#"
:root{color-scheme:light dark;--fg:#111;--bg:#fff;--mut:#666;--line:#e5e5e5;--acc:#2563eb;--ok:#16a34a;--bad:#dc2626}
@media(prefers-color-scheme:dark){:root{--fg:#eee;--bg:#111;--mut:#999;--line:#2a2a2a}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:640px;margin:0 auto;padding:32px 20px}h1{font-size:18px;margin:0 0 20px}h2{font-size:20px;margin:0 0 6px}
.card{border:1px solid var(--line);border-radius:10px;padding:18px;margin:0 0 14px}.mut{color:var(--mut);font-size:13px}
a.btn,button{display:inline-block;padding:9px 14px;border-radius:8px;border:1px solid var(--line);background:transparent;color:var(--fg);font:inherit;cursor:pointer;text-decoration:none}
button.p,a.btn.p{background:var(--acc);border-color:var(--acc);color:#fff}button.bad{border-color:var(--bad);color:var(--bad)}
input[type=password],input[type=text],textarea{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--fg);font:inherit}
ol{padding-left:20px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px}.flash{background:color-mix(in srgb,var(--ok) 12%,transparent);border:1px solid var(--ok);padding:10px 14px;border-radius:8px;margin-bottom:16px}
.err{background:color-mix(in srgb,var(--bad) 12%,transparent);border:1px solid var(--bad);padding:10px 14px;border-radius:8px;margin-bottom:16px}code{font-size:13px}
"#;

fn layout(title: &str, body: String) -> String {
    format!("<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><meta name=referrer content=no-referrer><title>{} · tokenstash</title><style>{CSS}</style></head><body><main><h1>tokenstash inbox</h1>{body}</main></body></html>", esc(title))
}

fn page_index(list: &[Task], flash: Option<&str>) -> String {
    let mut b = String::new();
    if let Some(f) = flash {
        b.push_str(&format!("<div class=flash>✓ {}</div>", esc(f)));
    }
    if list.is_empty() {
        b.push_str("<p class=mut>No open tasks. Your agents have everything they need.</p>");
    }
    for t in list {
        let what = match t.kind {
            TaskKind::Secret => format!("<code>{}</code>", esc(&t.name.clone().unwrap_or_default())),
            TaskKind::Approval => format!("approve {}", esc(&crate::util::approval_names(&t.names).join(", "))),
            TaskKind::Human => esc(&t.title),
        };
        b.push_str(&format!(
            "<div class=card><div class=mut>{} · {}</div><h2>{}</h2><div class=mut>{}</div><div class=row><a class='btn p' href='/t/{}'>Open →</a></div></div>",
            esc(&tokenstash_core::project::short(std::path::Path::new(&t.project))), esc(&t.agent), what, esc(&t.title), t.id
        ));
    }
    layout("Inbox", b)
}

/// The second half of the double submit. A hidden field rather than a header because these
/// are plain HTML forms with no JavaScript.
fn csrf_field(token: &str) -> String {
    format!("<input type=hidden name=t value=\"{}\">", esc(token))
}

fn page_task(t: &Task, err: Option<&str>, token: &str) -> String {
    let csrf = csrf_field(token);
    let mut b = String::new();
    b.push_str("<p><a href='/'>← all tasks</a></p>");
    if let Some(e) = err {
        b.push_str(&format!("<div class=err>{}</div>", esc(e)));
    }
    b.push_str(&format!("<div class=card><div class=mut>{} · requested by {}</div><h2>{}</h2>", esc(&tokenstash_core::project::short(std::path::Path::new(&t.project))), esc(&t.agent), esc(&t.title)));
    if let Some(w) = &t.why { b.push_str(&format!("<p>{}</p>", esc(w))); }
    if let Some(u) = &t.url { b.push_str(&format!("<div class=row><a class='btn p' href='{0}' target=_blank rel=noopener>Open {1} ↗</a></div>", esc(u), esc(u.trim_start_matches("https://").split('/').next().unwrap_or(u)))); }
    if !t.steps.is_empty() {
        b.push_str("<ol>");
        for s in &t.steps { b.push_str(&format!("<li>{}</li>", esc(s))); }
        b.push_str("</ol>");
    }
    if t.status != TaskStatus::Pending {
        b.push_str(&format!("<p class=mut>This task is {}.</p></div>", t.status.as_str()));
        return layout(&t.title, b);
    }
    match t.kind {
        TaskKind::Secret => {
            b.push_str(&format!(
                "<form method=post autocomplete=off>{csrf}<label class=mut for=v>{}</label><input id=v type=password name=value autocomplete=off autofocus placeholder='paste here — never shown, never sent anywhere but your keychain'>{}<label class=mut style='display:block;margin-top:8px'><input type=checkbox name=skip_check value=1> skip the provider check (store even if it cannot be verified)</label><div class=row><button class=p type=submit>Store &amp; inject</button><button class=bad name=action value=deny formnovalidate>Decline</button></div></form>",
                esc(&t.name.clone().unwrap_or_default()),
                t.pattern.as_ref().map(|p| format!("<div class=mut>must match <code>{}</code></div>", esc(p))).unwrap_or_default()
            ));
        }
        TaskKind::Approval => {
            b.push_str(&format!("<p>Keys: <code>{}</code></p><form method=post>{csrf}<div class=row><button class=p name=action value=allow>Allow for this project</button><button class=bad name=action value=deny>Deny</button></div></form>",
                crate::util::approval_names(&t.names).iter().map(|n| esc(n)).collect::<Vec<_>>().join("</code>, <code>")));
        }
        TaskKind::Human => {
            let note = if t.expects == "text" {
                "<textarea name=note rows=3 placeholder='your answer'></textarea><div class=mut>This answer is sent back to the agent. Never paste a secret here — the agent should request secrets with <code>tokenstash need</code>.</div>"
            } else {
                "<input type=text name=note placeholder='optional note (shown to the agent)'>"
            };
            b.push_str(&format!("<form method=post>{csrf}{note}<div class=row><button class=p name=action value=done>Done</button><button class=bad name=action value=deny>Can't do this</button></div></form>"));
        }
    }
    b.push_str("</div>");
    layout(&t.title, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_field_carries_the_token_and_escapes_it() {
        assert_eq!(csrf_field("abc123"), "<input type=hidden name=t value=\"abc123\">");
        // The token is hex so this cannot happen, but the field must never be an injection point.
        assert_eq!(csrf_field("\"><script>"), "<input type=hidden name=t value=\"&quot;&gt;&lt;script&gt;\">");
    }

    #[test]
    fn parse_form_reads_the_csrf_field_out_of_a_body() {
        let f = parse_form("value=sk-abc&t=deadbeef&skip_check=1");
        assert_eq!(f.get("t").map(String::as_str), Some("deadbeef"));
        assert_eq!(f.get("value").map(String::as_str), Some("sk-abc"));
        // A body with no token at all authenticates nothing.
        assert!(!parse_form("value=sk-abc").contains_key("t"));
    }
}
