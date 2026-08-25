//! Minimal MCP server over stdio (newline-delimited JSON-RPC 2.0).
//! Hand-rolled on purpose: five tools, no SDK version churn. Tool results never contain values.
//!
//! Nor do they contain the inbox session token. Everything written here lands in the model's
//! context, and the token is the credential that lets its holder ANSWER a task — store a value
//! under a real key name, approve a trust gate. Giving that to the model would let it answer
//! its own requests and self-approve the gates that exist to ask a person. So every `inbox`
//! field below uses `util::inbox_url` (bare); the tokened form goes to the desktop
//! notification and `tokenstash open`, which only a human reads. See `crate::inbox_auth`.

use crate::cmd::need::notify_pending;
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
                if let Some(n) = params.pointer("/clientInfo/name").and_then(|v| v.as_str()) { agent = n.to_string(); }
                let pv = params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or(PROTOCOL);
                result(id, json!({
                    "protocolVersion": pv,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "tokenstash", "version": env!("CARGO_PKG_VERSION") },
                    "instructions": "Call secrets_request for any API key or secret the project needs instead of asking the user to paste it. Values are written to the project's env file; they are never returned. If a result is pending, keep working and call task_check later."
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
                    "blocking": { "type": "boolean", "description": "Wait for the user instead of returning pending. Default false." },
                    "timeout_s": { "type": "integer", "default": 600 }
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
                "project": { "type": "string" }, "blocking": { "type": "boolean" }, "timeout_s": { "type": "integer", "default": 600 }
            }, "required": ["title"] }
        },
        { "name": "task_check", "description": "Check the status of a task (pending | answered | denied | expired). For secret tasks, answered means the value is now in the env file.", "inputSchema": { "type": "object", "properties": { "task_id": { "type": "string" } }, "required": ["task_id"] } },
        { "name": "task_list", "description": "List open tasks for the project.", "inputSchema": { "type": "object", "properties": { "project": { "type": "string" } } } },
        { "name": "secrets_list", "description": "List the names (never values) of secrets the user already has, so you can request the right ones.", "inputSchema": { "type": "object", "properties": {} } }
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
    let timeout = Duration::from_secs(args.get("timeout_s").and_then(|v| v.as_u64()).unwrap_or(600));
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
            for s in &specs {
                let opts = NeedOpts {
                    req: SecretRequest { why: s.why.clone(), url: s.url.clone(), steps: s.steps.clone(), pattern: s.pattern.clone() },
                    identity: s.identity.clone(), blocking: false, timeout, force: false, require_approval: false,
                };
                results.extend(need::need(&app.ctx(), &project, agent, std::slice::from_ref(&s.name), &opts)?);
            }
            if results.iter().any(|o| o.is_pending()) {
                notify_pending(&app, &project, agent, &results);
                if blocking {
                    // wait on the tasks already filed (each carries its own identity)
                    need::wait(&app.ctx(), &project, &mut results, timeout)?;
                }
            }
            let pending = results.iter().any(|o| o.is_pending());
            Ok((json!({
                "results": results,
                "env_file": project.join(&app.cfg.env_file),
                "inbox": util::inbox_url_agent(&app.cfg, None, if pending { crate::notify::inbox_state(&app.cfg) } else { crate::notify::Inbox::Down }),
                "next": if pending { "Show the user the `inbox` link — it works as-is for pasting the key (if the page asks for the full session, the user clicks the desktop notification or runs `tokenstash open`). Continue other work; call task_check with the task_id later." } else { "Done." }
            }), false))
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
                let start = std::time::Instant::now();
                while task.status == tokenstash_core::db::TaskStatus::Pending && start.elapsed() < timeout {
                    std::thread::sleep(Duration::from_millis(500));
                    app.db.expire_overdue()?;
                    task = app.db.get_task(&task.id)?.unwrap_or(task);
                }
            }
            Ok((json!({ "task_id": task.id, "status": task.status, "note": task.note, "inbox": util::inbox_url_agent(&app.cfg, Some(&task.id), crate::notify::inbox_state(&app.cfg)) }), false))
        }
        "task_check" => {
            let id = args.get("task_id").and_then(|v| v.as_str()).unwrap_or("");
            app.db.expire_overdue()?;
            // Scoped to this project: a task id (or prefix) from another project reveals
            // that project's path and state to a model that has no business with it.
            let pid = project.to_string_lossy().to_string();
            match app.db.find_task(id)?.filter(|t| t.project == pid) {
                Some(t) => Ok((json!({ "task_id": t.id, "kind": t.kind, "status": t.status, "name": t.name, "title": t.title, "note": t.note, "env_file": std::path::Path::new(&t.project).join(&app.cfg.env_file) }), false)),
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
        "secrets_list" => {
            let list = app.db.list_secrets()?;
            let names: Vec<Value> = list.iter().map(|s| json!({ "name": s.name, "identity": s.identity, "provider": s.provider, "sensitive": s.sensitive, "stale": s.stale })).collect();
            Ok((json!({ "secrets": names }), false))
        }
        other => anyhow::bail!("unknown tool {other}"),
    }
}
