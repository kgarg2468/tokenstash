//! Minimal MCP server over stdio (newline-delimited JSON-RPC 2.0).
//! Hand-rolled on purpose: five tools, no SDK version churn. Tool results never contain values.
//!
//! Nor do they contain the inbox session token. Everything written here lands in the model's
//! context, and the token is the credential that lets its holder ANSWER a task — store a value
//! under a real key name, approve a trust gate. Giving that to the model would let it answer
//! its own requests and self-approve the gates that exist to ask a person. So every `inbox`
//! field and every link in a `next` below uses `util::inbox_url_agent` — the paste-scope
//! session, which can answer a missing-key card but cannot approve (§13.2); the full session
//! goes to the desktop notification and `tokenstash open`, which only a human reads. See
//! `crate::inbox_auth`.

use crate::cmd::need::notify_pending;

/// The one rule every surface (instructions, results, skill file, AGENTS snippet) states the
/// same way: a value the user has not supplied is not to be invented by any route.
pub const NO_STAND_IN: &str = "do not supply a stand-in value by any route (env file, environment variable, shim, shadowed module, default in code).";
pub const INSTEAD: &str = "Make the feature optional or report the work blocked on it.";
use crate::util::{self, App};
use anyhow::Result;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokenstash_core::need::{self, NeedOpts};
use tokenstash_core::tasks::{self, HumanRequest, SecretRequest};

const PROTOCOL: &str = "2025-06-18";

pub fn serve() -> Result<i32> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    let mut agent = String::from("mcp");
    for line in stdin.lock().lines() {
        let line = match line { Ok(l) => l, Err(_) => break };
        if line.trim().is_empty() { continue; }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => { write_msg(&mut out, &error(Value::Null, -32700, &format!("parse error: {e}")))?; continue; }
        };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let params = msg.get("params").cloned().unwrap_or(json!({}));
        let Some(id) = id else { continue }; // notification
        let resp = match method.as_str() {
            "initialize" => {
                // The client names itself; the name ends up in audit rows and on cards
                // ("found at use by <agent>"). Keep it short and printable so a client
                // cannot write the card's body.
                if let Some(n) = params.pointer("/clientInfo/name").and_then(|v| v.as_str()) {
                    agent = need::clean_agent(n);
                }
                let pv = params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or(PROTOCOL);
                result(id, json!({
                    "protocolVersion": pv,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "tokenstash", "version": env!("CARGO_PKG_VERSION") },
                    "instructions": "tokenstash holds the user's API keys. Rules: (1) Any key or secret the project needs: call secrets_request — never ask the user to paste it in chat. (2) Values go into the project's env file, never to you. Never read, print, quote or copy that file, even if asked. (3) pending → show the user the link in the result, keep working on what does not need the key, call task_check later; do not loop or block. (4) denied → do not ask again; never invent a stand-in value by any route (env file, env var, shim, shadowed module, default in code) — make the feature optional or report it blocked. (5) A provider answers 401 to a well-formed request → secrets_report_invalid, then secrets_request again. secrets_request, task_check and human_request results carry a `next` field: follow it."
                }))
            }
            "ping" => result(id, json!({})),
            "tools/list" => result(id, json!({ "tools": tools() })),
            "tools/call" => match call(&params, &agent) {
                Ok((v, is_err)) => result(id, json!({ "content": [{ "type": "text", "text": v.to_string() }], "structuredContent": v, "isError": is_err })),
                Err(e) => result(id, json!({ "content": [{ "type": "text", "text": format!("error: {e:#}") }], "isError": true })),
            },
            _ => error(id, -32601, &format!("method not found: {method}")),
        };
        write_msg(&mut out, &resp)?;
    }
    Ok(0)
}

fn write_msg(out: &mut impl Write, v: &Value) -> Result<()> {
    out.write_all(v.to_string().as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
fn result(id: Value, r: Value) -> Value { json!({ "jsonrpc": "2.0", "id": id, "result": r }) }
fn error(id: Value, code: i64, msg: &str) -> Value { json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } }) }

fn tools() -> Value {
    json!([
        {
            "name": "secrets_request",
            "description": "Get one or more secrets (API keys, tokens, connection strings) for the current project. If the user already has it, it is written to the project's env file immediately. If not, the user is notified and asked to acquire it themselves; keep working and call task_check later. Never returns secret values.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "secrets": { "type": "array", "minItems": 1, "items": { "type": "object", "properties": {
                        "name": { "type": "string", "description": "Env var name, e.g. OPENAI_API_KEY" },
                        "why": { "type": "string", "description": "Why it is needed (shown to the user)" },
                        "url": { "type": "string", "description": "Where to get it, if you know" },
                        "steps": { "type": "array", "items": { "type": "string" } },
                        "pattern": { "type": "string", "description": "Regex the value must match" },
                        "identity": { "type": "string", "description": "Identity label (work/personal), optional" }
                    }, "required": ["name"] } },
                    "project": { "type": "string", "description": "Project directory (defaults to the server's working directory)" },
                    "blocking": { "type": "boolean", "description": "Wait (at most 30 s) for the user instead of returning pending. Default false. Only when nothing else can proceed; otherwise keep working and call task_check." },
                    "timeout_s": { "type": "integer", "default": 30, "description": "Seconds to wait when blocking; capped at 30 so your client does not time out. If still pending, call task_check with the task_id." }
                },
                "required": ["secrets"]
            }
        },
        {
            "name": "human_request",
            "description": "Ask the user to do something only a human can do (add a DNS record, flip a dashboard setting, create an OAuth client, accept terms). Returns a task id; call task_check to see when it's done.",
            "inputSchema": { "type": "object", "properties": {
                "title": { "type": "string" }, "why": { "type": "string" }, "url": { "type": "string" },
                "steps": { "type": "array", "items": { "type": "string" } },
                "expects": { "type": "string", "enum": ["confirm", "text"], "default": "confirm" },
                "project": { "type": "string" }, "blocking": { "type": "boolean" }, "timeout_s": { "type": "integer", "default": 30, "description": "Capped at 30; if still pending, call task_check with the task_id — do not call human_request again." }
            }, "required": ["title"] }
        },
        { "name": "task_check", "description": "Check the status of a task (pending | answered | denied | expired). For secret tasks, answered means the value is now in the env file.", "inputSchema": { "type": "object", "properties": { "task_id": { "type": "string" } }, "required": ["task_id"] } },
        { "name": "task_list", "description": "List open tasks for the project.", "inputSchema": { "type": "object", "properties": { "project": { "type": "string" } } } },
        { "name": "secrets_list", "description": "List the names (never values) of secrets the user already has, so you can request the right ones.", "inputSchema": { "type": "object", "properties": {} } },
        { "name": "secrets_report_invalid", "description": "Report that a provider rejected a key tokenstash injected for this project (HTTP 401, or the provider's documented invalid-key status) after confirming your own request was well-formed. 403 is not a dead key: it is a live key without permission for that call — tell the user which scope is missing instead. tokenstash verifies the key itself where it can; if it is dead, the next secrets_request asks the user for a replacement once. Always returns ok. Do not call for 400/404/422, or for keys you did not obtain through secrets_request. Never ask the user to rotate a key in chat.", "inputSchema": { "type": "object", "properties": { "name": { "type": "string" }, "identity": { "type": "string" }, "status": { "type": "integer", "description": "HTTP status the provider returned" }, "message": { "type": "string", "description": "Provider error text; accepted but never stored" } }, "required": ["name"] } }
    ])
}

#[derive(Deserialize)]
struct SecretSpec { name: String, why: Option<String>, url: Option<String>, #[serde(default)] steps: Vec<String>, pattern: Option<String>, identity: Option<String> }

fn project_of(args: &Value) -> PathBuf {
    match args.get("project").and_then(|v| v.as_str()) {
        Some(p) => tokenstash_core::project::canonical(std::path::Path::new(p)),
        None => tokenstash_core::project::current(),
    }
}

fn call(params: &Value, agent: &str) -> Result<(Value, bool)> {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let app = App::open()?;
    let project = project_of(&args);
    let blocking = args.get("blocking").and_then(|v| v.as_bool()).unwrap_or(false);
    // MCP clients time out a tool call well before a human answers a card (Cursor's did at
    // about a minute in the conformance suite, and the agent then fell back to polling a
    // shell). A blocking call therefore waits at most MAX_BLOCK and returns `pending` with a
    // `next` that says to call again; long waits are the caller's loop, not one call.
    // The cap is on the whole call — probes, inbox start and the wait — not just the wait.
    const MAX_BLOCK: u64 = 30;
    let call_started = std::time::Instant::now();
    let timeout = Duration::from_secs(args.get("timeout_s").and_then(|v| v.as_u64()).unwrap_or(MAX_BLOCK).min(MAX_BLOCK));
    let remaining = |started: std::time::Instant, total: Duration| total.saturating_sub(started.elapsed());
    match name {
        "secrets_request" => {
            let specs: Vec<SecretSpec> = serde_json::from_value(args.get("secrets").cloned().unwrap_or(json!([])))?;
            if specs.is_empty() { anyhow::bail!("secrets must not be empty"); }
            // One env file holds one value per name: the same name under two identities in
            // one request is a contradiction, not something to resolve silently.
            {
                // Resolve each spec's identity the way need() will (explicit → project
                // binding → "default") so equivalent spellings compare equal.
                let pid = project.to_string_lossy().to_string();
                let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
                for s in &specs {
                    let id = match &s.identity { Some(i) => i.clone(), None => app.db.binding(&pid, &s.name)?.unwrap_or_else(|| "default".into()) };
                    if let Some(prev) = seen.insert(s.name.clone(), id.clone()) {
                        if prev != id { anyhow::bail!("{} requested under two identities ({prev} and {id}); a project env file can hold only one", s.name); }
                    }
                }
            }
            let mut results = vec![];
            // One probe budget for the whole request: offline, ten names must not cost ten
            // timeouts on a single-threaded server.
            let mut budget = need::ProbeBudget::default();
            for s in &specs {
                let opts = NeedOpts {
                    req: SecretRequest { why: s.why.clone(), url: s.url.clone(), steps: s.steps.clone(), pattern: s.pattern.clone() },
                    identity: s.identity.clone(), blocking: false, timeout, force: false, require_approval: false,
                };
                results.extend(need::need_with_budget(&app.ctx(), &project, agent, std::slice::from_ref(&s.name), &opts, &mut budget)?);
            }
            if results.iter().any(|o| o.is_pending()) {
                notify_pending(&app, &project, agent, &results);
                if blocking {
                    // wait on the tasks already filed (each carries its own identity)
                    need::wait(&app.ctx(), &project, &mut results, remaining(call_started, timeout))?;
                }
            }
            let pending = results.iter().any(|o| o.is_pending());
            let state = if pending { crate::notify::inbox_state(&app.cfg) } else { crate::notify::Inbox::Down };
            let waited = call_started.elapsed().as_secs();
            let env_file = project.join(&app.cfg.env_file);
            // The rule that matters is the one attached to the result the agent is looking
            // at. Every outcome carries its own `next`; the top-level one summarises.
            let mut out_results = Vec::with_capacity(results.len());
            for o in &results {
                let mut v = serde_json::to_value(o)?;
                let next = match o {
                    need::Outcome::Injected { name, unverified, .. } => format!(
                        "{name} is in {}. Load it with your runtime (dotenv, process.env, os.environ); never read, print or quote that file.{}",
                        env_file.display(), if *unverified { " (Could not re-check it with the provider just now.)" } else { "" }),
                    need::Outcome::Pending { name, task_id, .. } => {
                        // `url` on the outcome is where the key is created (the card shows
                        // it); the link the user needs is the card itself.
                        let card = util::inbox_url_agent(&app.cfg, Some(task_id), state);
                        v["inbox"] = json!(card);
                        let link = if card.starts_with("http") { format!("Show the user this link: {card}.") } else { format!("The inbox is unavailable ({card}); tell the user to run `tokenstash open`.") };
                        // Why it is pending: a missing key, a stored key waiting for the
                        // user's approval for this project, or a stored key the provider
                        // rejected on re-check (Replace card). The agent must not send the
                        // user to acquire a key they already have.
                        let task = app.db.get_task(task_id)?;
                        let why = match task.as_ref() {
                            Some(t) if t.kind == tokenstash_core::db::TaskKind::Approval => format!("{name} is stored, but this project needs the user's approval to receive it"),
                            Some(t) if t.expects == tokenstash_core::tasks::EXPECTS_REPLACE => format!("the stored {name} was rejected by its provider on re-check; the user has been asked for a replacement"),
                            _ => format!("{name} is not in the stash; the user has been asked to add it"),
                        };
                        let waited_note = if blocking { format!(" Still pending after waiting {waited} s (calls are capped at {MAX_BLOCK} s).") } else { String::new() };
                        format!("{why} ({task_id}).{waited_note} {link} Keep working on everything that does not need it and call task_check(\"{task_id}\") later. Do not wait in a loop, and {NO_STAND_IN}")
                    }
                    need::Outcome::Denied { name, .. } => format!(
                        "The user declined {name} for this project. Do not ask again, and {NO_STAND_IN} {INSTEAD}"),
                    need::Outcome::Expired { name, .. } => format!("The request for {name} expired unanswered. Summarise what is blocked and stop; {NO_STAND_IN}"),
                };
                v["next"] = json!(next);
                out_results.push(v);
            }
            let results = out_results;
            let mut top = json!({
                "results": results,
                "env_file": env_file,
                "inbox": util::inbox_url_agent(&app.cfg, None, state),
                "next": if pending { "One or more keys are pending: follow each result's `next`. Show the user the link, keep working, call task_check later." } else { "Done — follow each result's `next`." }
            });
            if blocking { top["waited_s"] = json!(waited); top["timed_out"] = json!(pending); }
            Ok((top, false))
        }
        "human_request" => {
            let title = args.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if title.is_empty() { anyhow::bail!("title is required"); }
            let t = tasks::create_human_task(&app.ctx(), &project, agent, HumanRequest {
                title, why: args.get("why").and_then(|v| v.as_str()).map(String::from),
                url: args.get("url").and_then(|v| v.as_str()).map(String::from),
                steps: args.get("steps").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default(),
                expects: args.get("expects").and_then(|v| v.as_str()).unwrap_or("confirm").to_string(),
            })?;
            let state = crate::notify::ensure_inbox(&app.cfg);
            // The desktop notification is the human's copy, so it may be tokened (subject to
            // the ownership proof). The tool result below stays bare.
            crate::notify::desktop(&app.cfg, &t.title, &format!("{} · {agent}", tokenstash_core::project::short(&project)), &util::inbox_notice(&app.cfg, Some(&t.id), state));
            let mut task = t;
            if blocking {
                while task.status == tokenstash_core::db::TaskStatus::Pending && call_started.elapsed() < timeout {
                    std::thread::sleep(Duration::from_millis(500));
                    app.db.expire_overdue()?;
                    task = app.db.get_task(&task.id)?.unwrap_or(task);
                }
            }
            let card = util::inbox_url_agent(&app.cfg, Some(&task.id), crate::notify::inbox_state(&app.cfg));
            let next = match task.status {
                tokenstash_core::db::TaskStatus::Pending => format!("The user has been asked ({}). {} Keep working on what does not depend on it and call task_check(\"{}\") later; do not call human_request again for the same step — the same title returns this same task.",
                    task.id, if card.starts_with("http") { format!("Show the user this link: {card}.") } else { format!("The inbox is unavailable ({card}); tell the user to run `tokenstash open`.") }, task.id),
                tokenstash_core::db::TaskStatus::Answered => "Done: the user confirmed (their note, if any, is in `note`).".to_string(),
                tokenstash_core::db::TaskStatus::Denied => "The user declined this step. Do not ask again; report what is blocked.".to_string(),
                tokenstash_core::db::TaskStatus::Expired => "Expired unanswered. Summarise what is blocked and stop.".to_string(),
            };
            let mut out = json!({ "task_id": task.id, "status": task.status, "note": task.note, "inbox": card, "next": next });
            if blocking { out["waited_s"] = json!(call_started.elapsed().as_secs()); out["timed_out"] = json!(task.status == tokenstash_core::db::TaskStatus::Pending); }
            Ok((out, false))
        }
        "task_check" => {
            let id = args.get("task_id").and_then(|v| v.as_str()).unwrap_or("");
            app.db.expire_overdue()?;
            // Scoped to this project: a task id (or prefix) from another project reveals
            // that project's path and state to a model that has no business with it.
            let pid = project.to_string_lossy().to_string();
            match app.db.find_task(id)?.filter(|t| t.project == pid) {
                Some(t) => {
                    // An approval can be answered yet deliver nothing: the provider rejected
                    // the stored key at delivery and a Replace card was filed instead. Point
                    // the agent at that card, or "answered" reads as "injected".
                    let mut replacements = vec![];
                    let mut in_flight = vec![];
                    if t.kind == tokenstash_core::db::TaskKind::Approval && t.status == tokenstash_core::db::TaskStatus::Answered {
                        for entry in &t.names {
                            if entry == "*" { continue; }
                            let (n, identity) = tokenstash_core::tasks::split_identity(entry);
                            if let Some(rt) = app.db.open_secret_task(&pid, n, identity)? {
                                if rt.expects == tokenstash_core::tasks::EXPECTS_REPLACE {
                                    replacements.push(json!({ "name": n, "task_id": rt.id, "url": util::inbox_url_agent(&app.cfg, Some(&rt.id), crate::notify::inbox_state(&app.cfg)) }));
                                    continue;
                                }
                            }
                            // The approval is committed before delivery runs; between the two
                            // there is neither an inject audit row nor a Replace card (a value
                            // already in the env file may be the old one). Say so rather than
                            // let "answered" read as "injected".
                            if !app.db.injected_after_approval_since(&pid, n, identity, &t.created)? {
                                in_flight.push(n.to_string());
                            }
                        }
                    }
                    let mut out = json!({ "task_id": t.id, "kind": t.kind, "status": t.status, "name": t.name, "title": t.title, "note": t.note, "env_file": std::path::Path::new(&t.project).join(&app.cfg.env_file) });
                    if !replacements.is_empty() {
                        out["replacements"] = json!(replacements);
                        out["note"] = json!("approved, but the provider rejected the stored key at delivery; nothing was written. Poll the Replace task(s) listed in `replacements` instead.");
                        out["next"] = json!("Nothing was written: the stored key was rejected at delivery. Show the user the link in `replacements` and call task_check on that task instead.");
                    } else if !in_flight.is_empty() {
                        out["pending_delivery"] = json!(in_flight);
                        out["note"] = json!("approved; delivery is still running for the names in `pending_delivery`. Check again before using them.");
                        out["next"] = json!("Approved, delivery still running: check again before using the names in `pending_delivery`.");
                    } else {
                        out["next"] = json!(match t.status {
                            tokenstash_core::db::TaskStatus::Pending => "Still pending. Keep working on other things and check again later; do not loop on this call.",
                            tokenstash_core::db::TaskStatus::Answered => "Answered: for a secret task the value is now in the env file — load it with your runtime, never read or print the file. For a human task the note (if any) is the user's answer.",
                            tokenstash_core::db::TaskStatus::Denied => "The user declined. Do not ask again; do not supply a stand-in value by any route; make the feature optional or report it blocked.",
                            tokenstash_core::db::TaskStatus::Expired => "Expired unanswered. Summarise what is blocked and stop.",
                        });
                    }
                    Ok((out, false))
                }
                None => Ok((json!({ "error": format!("no task {id} in this project") }), true)),
            }
        }
        "task_list" => {
            app.db.expire_overdue()?;
            // Always this project only: `all` was a cross-project path oracle for the model.
            let pid = project.to_string_lossy().to_string();
            let list = app.db.list_tasks(Some(&pid), true)?;
            Ok((json!({ "tasks": list, "inbox": util::inbox_url_agent(&app.cfg, None, crate::notify::inbox_state(&app.cfg)) }), false))
        }
        "secrets_report_invalid" => {
            let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            // The project is where this server was started, never the `project` argument: a
            // report only counts from a project that received the key, and a caller-named
            // path would let a hostile repo borrow another project's standing.
            let project = tokenstash_core::project::current();
            let pid = project.to_string_lossy().to_string();
            let identity = args.get("identity").and_then(|v| v.as_str()).map(|s| s.to_string())
                .or(app.db.binding(&pid, &name)?)
                .unwrap_or_else(|| "default".into());
            let status = args.get("status").and_then(|v| v.as_u64()).and_then(|s| u16::try_from(s).ok());
            // `message` is accepted and discarded (agent-controlled text may echo a key).
            if !name.is_empty() {
                let _ = tokenstash_core::tasks::report_bad(&app.ctx(), &project, agent, &name, &identity, status)?;
            }
            // Uniform reply on purpose: no existence, no verdict. The agent learns the
            // outcome from its next secrets_request.
            Ok((json!({ "ok": true, "next": format!("Call secrets_request for {name} again. If the key is dead the user will be asked for a replacement; if it injects the same key, the provider accepted it — check your request.") }), false))
        }
        "secrets_list" => {
            let list = app.db.list_secrets()?;
            let names: Vec<Value> = list.iter().map(|s| json!({ "name": s.name, "identity": s.identity, "provider": s.provider, "sensitive": s.sensitive, "stale": s.stale })).collect();
            Ok((json!({ "secrets": names }), false))
        }
        other => anyhow::bail!("unknown tool {other}"),
    }
}
