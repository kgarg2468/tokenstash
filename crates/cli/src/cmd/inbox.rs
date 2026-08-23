//! Localhost inbox: the human surface. One click from the notification to the vendor's page,
//! paste, submit. Binds 127.0.0.1 only. Exits after 30 idle minutes with no open tasks.

use crate::util::App;
use anyhow::Result;
use clap::Args;
use secrecy::SecretString;
use std::collections::HashMap;
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

pub fn serve(a: InboxArgs) -> Result<i32> {
    let app = App::open()?;
    let port = a.port.unwrap_or(app.cfg.inbox_port);
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
                if let Err(e) = handle(&app, req) {
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

fn handle(app: &App, mut req: Request) -> Result<()> {
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    let method = req.method().as_str().to_string();
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
        let flash = url.split('?').nth(1).and_then(|q| parse_form(q).remove("m"));
        return respond(req, 200, "text/html; charset=utf-8", page_index(&list, flash.as_deref()));
    }
    if let Some(id) = path.strip_prefix("/t/") {
        let id = id.trim_end_matches('/').to_string();
        let Some(task) = app.db.find_task(&id)? else { return respond(req, 404, "text/plain", "no such task".into()) };
        if method == "GET" {
            return respond(req, 200, "text/html; charset=utf-8", page_task(&task, None));
        }
        if method == "POST" {
            let mut body = String::new();
            req.as_reader().read_to_string(&mut body)?;
            let form = parse_form(&body);
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
                Err(e) => respond(req, 200, "text/html; charset=utf-8", page_task(&task, Some(&format!("{e:#}")))),
            };
        }
    }
    respond(req, 404, "text/plain", "not found".into())
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
    format!("<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>{} · tokenstash</title><style>{CSS}</style></head><body><main><h1>tokenstash inbox</h1>{body}</main></body></html>", esc(title))
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
            TaskKind::Approval => format!("approve {}", esc(&t.names.iter().filter(|n| n.as_str() != "*").cloned().collect::<Vec<_>>().join(", "))),
            TaskKind::Human => esc(&t.title),
        };
        b.push_str(&format!(
            "<div class=card><div class=mut>{} · {}</div><h2>{}</h2><div class=mut>{}</div><div class=row><a class='btn p' href='/t/{}'>Open →</a></div></div>",
            esc(&tokenstash_core::project::short(std::path::Path::new(&t.project))), esc(&t.agent), what, esc(&t.title), t.id
        ));
    }
    layout("Inbox", b)
}

fn page_task(t: &Task, err: Option<&str>) -> String {
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
                "<form method=post><label class=mut for=v>{}</label><input id=v type=password name=value autocomplete=off autofocus placeholder='paste here — never shown, never sent anywhere but your keychain'>{}<div class=row><button class=p type=submit>Store &amp; inject</button><button class=bad name=action value=deny formnovalidate>Decline</button></div></form>",
                esc(&t.name.clone().unwrap_or_default()),
                t.pattern.as_ref().map(|p| format!("<div class=mut>must match <code>{}</code></div>", esc(p))).unwrap_or_default()
            ));
            b.push_str("<p class=mut style='margin-top:10px'><label><input type=checkbox name=skip_check form=f2> </label>If the provider check fails you'll see it here and nothing will be stored.</p>");
        }
        TaskKind::Approval => {
            b.push_str(&format!("<p>Keys: <code>{}</code></p><form method=post><div class=row><button class=p name=action value=allow>Allow for this project</button><button class=bad name=action value=deny>Deny</button></div></form>",
                esc(&t.names.iter().filter(|n| n.as_str() != "*").cloned().collect::<Vec<_>>().join("</code>, <code>"))));
        }
        TaskKind::Human => {
            let note = if t.expects == "text" { "<textarea name=note rows=3 placeholder='your answer'></textarea>" } else { "<input type=text name=note placeholder='optional note'>" };
            b.push_str(&format!("<form method=post>{note}<div class=row><button class=p name=action value=done>Done</button><button class=bad name=action value=deny>Can't do this</button></div></form>"));
        }
    }
    b.push_str("</div>");
    layout(&t.title, b)
}
