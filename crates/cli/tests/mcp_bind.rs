//! The MCP server serves one directory, decided once: the client's `roots` when offered
//! and answered, else its cwd — never a tool argument — and refuses to serve from
//! directories that are not projects (§13.1 rule 3, §13.5).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

fn tmp(name: &str) -> PathBuf {
    let p = Path::new("/tmp").join(format!("tokenstash-mcp-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A scripted MCP client talking to a real server process.
struct Client {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<serde_json::Value>,
}

impl Client {
    fn start(home: &Path, cwd: &Path, roots_capability: bool) -> Client {
        let mut child = Command::new(env!("CARGO_BIN_EXE_tokenstash"))
            .arg("mcp")
            .current_dir(cwd)
            .env("TOKENSTASH_HOME", home)
            .env("TOKENSTASH_STASH", "insecure-file")
            .env_remove("CLAUDECODE")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
            .spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines() {
                let Ok(l) = l else { break };
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&l) {
                    if tx.send(v).is_err() { break; }
                }
            }
        });
        let mut c = Client { child, stdin, lines: rx };
        let caps = if roots_capability { serde_json::json!({ "roots": { "listChanged": true } }) } else { serde_json::json!({}) };
        c.send(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "clientInfo": { "name": "test" }, "capabilities": caps } }));
        c.expect_id(1);
        c.send(serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        c
    }
    fn send(&mut self, v: serde_json::Value) { writeln!(self.stdin, "{v}").unwrap(); }
    fn next(&self, within: Duration) -> Option<serde_json::Value> { self.lines.recv_timeout(within).ok() }
    /// The response with this id (skipping anything else).
    fn expect_id(&self, id: u64) -> serde_json::Value {
        loop {
            let v = self.next(Duration::from_secs(20)).expect("a response before the timeout");
            if v.get("id") == Some(&serde_json::json!(id)) { return v; }
        }
    }
    /// The server's `roots/list` request, if it sends one soon.
    fn roots_request(&self) -> Option<serde_json::Value> {
        let v = self.next(Duration::from_millis(1500))?;
        if v.get("method").and_then(|m| m.as_str()) == Some("roots/list") { Some(v) } else { None }
    }
    fn answer_roots(&mut self, req: &serde_json::Value, uris: &[&str]) {
        let list: Vec<_> = uris.iter().map(|u| serde_json::json!({ "uri": u, "name": "r" })).collect();
        self.send(serde_json::json!({ "jsonrpc": "2.0", "id": req["id"].clone(), "result": { "roots": list } }));
    }
    fn call(&mut self, id: u64, tool: &str, args: serde_json::Value) -> serde_json::Value {
        self.send(serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": tool, "arguments": args } }));
        self.expect_id(id)
    }
    /// Where the server is bound: file a human task and read its project back.
    fn bound_project(&mut self, base: u64) -> Result<String, String> {
        let r = self.call(base, "human_request", serde_json::json!({ "title": format!("probe {base}") }));
        if r.pointer("/result/isError") == Some(&serde_json::json!(true)) {
            return Err(text_of(&r));
        }
        let l = self.call(base + 1, "task_list", serde_json::json!({}));
        let tasks = l.pointer("/result/structuredContent/tasks").and_then(|t| t.as_array()).cloned().unwrap_or_default();
        Ok(tasks.iter().find(|t| t.get("title").and_then(|x| x.as_str()) == Some(&format!("probe {base}"))).and_then(|t| t.get("project")).and_then(|p| p.as_str()).unwrap_or("").to_string())
    }
}

impl Drop for Client {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}

fn text_of(v: &serde_json::Value) -> String {
    v.pointer("/result/content/0/text").and_then(|t| t.as_str()).unwrap_or("").to_string()
}

fn file_uri(p: &Path) -> String { format!("file://{}", p.display()) }

#[test]
fn refused_directories_never_serve() {
    let home = tmp("home-refused");
    for cwd in [PathBuf::from("/"), dirs::home_dir().unwrap(), PathBuf::from("/tmp")] {
        let mut c = Client::start(&home, &cwd, false);
        let r = c.call(2, "secrets_list", serde_json::json!({}));
        assert_eq!(r.pointer("/result/isError"), Some(&serde_json::json!(true)), "{cwd:?}: {r}");
        assert!(text_of(&r).contains("no project bound"), "{cwd:?}: {}", text_of(&r));
        assert!(text_of(&r).contains("Restart your agent in the project directory"));
    }
}

#[test]
fn schemas_name_no_project_and_the_server_refuses_another_directory() {
    let home = tmp("home-schemas");
    let a = tmp("proj-a");
    let b = tmp("proj-b");
    let mut c = Client::start(&home, &a, false);
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list" }));
    let tools = c.expect_id(5).to_string();
    assert!(!tools.contains("\"project\""), "no schema may take a project: {tools}");
    assert_eq!(c.bound_project(10).unwrap(), a.canonicalize().unwrap().to_string_lossy());
    let r = c.call(20, "human_request", serde_json::json!({ "title": "Other", "project": b.to_string_lossy() }));
    assert!(text_of(&r).contains("does not act for"), "{}", text_of(&r));
    let r = c.call(21, "human_request", serde_json::json!({ "title": "Rel", "project": "." }));
    assert!(text_of(&r).contains("absolute path"), "{}", text_of(&r));
    let r = c.call(22, "human_request", serde_json::json!({ "title": "Same", "project": a.to_string_lossy() }));
    assert_ne!(r.pointer("/result/isError"), Some(&serde_json::json!(true)), "naming the bound directory is fine: {r}");
}

#[test]
fn without_the_roots_capability_no_request_is_sent_and_a_planted_answer_is_ignored() {
    let home = tmp("home-noroots");
    let proj = tmp("proj-noroots");
    let other = tmp("other-noroots");
    let mut c = Client::start(&home, &proj, false);
    assert!(c.roots_request().is_none(), "the server must not ask a client that did not offer roots");
    // an unsolicited "answer" must not rebind the server
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": "tokenstash-roots-1", "result": { "roots": [{ "uri": file_uri(&other), "name": "x" }] } }));
    assert_eq!(c.bound_project(10).unwrap(), proj.canonicalize().unwrap().to_string_lossy());
}

#[test]
fn a_single_root_binds_the_server_even_when_started_elsewhere() {
    let home = tmp("home-oneroot");
    let proj = tmp("proj-oneroot");
    let elsewhere = tmp("elsewhere-oneroot");
    let mut c = Client::start(&home, &elsewhere, true);
    let req = c.roots_request().expect("the server asks for roots");
    c.answer_roots(&req, &[&file_uri(&proj)]);
    assert_eq!(c.bound_project(10).unwrap(), proj.canonicalize().unwrap().to_string_lossy(), "bound to the root, not the cwd");
    // a request with a malformed id is not our answer: the server keeps waiting, then binds cwd
    let mut c = Client::start(&home, &elsewhere, true);
    let _req = c.roots_request().unwrap();
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": "someone-else", "result": { "roots": [{ "uri": file_uri(&proj), "name": "x" }] } }));
    assert_eq!(c.bound_project(10).unwrap(), elsewhere.canonicalize().unwrap().to_string_lossy());
}

#[test]
fn a_refused_root_fails_closed_even_though_cwd_is_fine() {
    let home = tmp("home-refroot");
    let proj = tmp("proj-refroot");
    let mut c = Client::start(&home, &proj, true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&file_uri(&dirs::home_dir().unwrap())]);
    let err = c.bound_project(10).unwrap_err();
    assert!(err.contains("your home directory"), "the root, not cwd, was the candidate: {err}");
}

#[test]
fn roots_uris_are_decoded_and_non_file_ones_ignored() {
    let home = tmp("home-decode");
    let elsewhere = tmp("elsewhere-decode");
    let spaced = tmp("proj with space");
    let sc = spaced.canonicalize().unwrap();
    // percent-encoded, trailing slash, `localhost` authority, a non-file scheme alongside
    let enc = format!("file://localhost{}/", sc.to_string_lossy().replace(' ', "%20"));
    let mut c = Client::start(&home, &elsewhere, true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&enc, "https://example.com/not-a-root", "vscode-vfs://x"]);
    assert_eq!(c.bound_project(10).unwrap(), sc.to_string_lossy(), "one usable root after decoding");
    // a symlinked root binds the directory it points at
    let real = tmp("proj-real");
    let link = Path::new("/tmp").join(format!("tokenstash-mcp-link-{}", std::process::id()));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let mut c = Client::start(&home, &elsewhere, true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&file_uri(&link)]);
    assert_eq!(c.bound_project(10).unwrap(), real.canonicalize().unwrap().to_string_lossy());
}

#[test]
fn several_roots_follow_the_rules() {
    let home = tmp("home-many");
    let parent = tmp("many-parent");
    let child = parent.join("child"); std::fs::create_dir_all(&child).unwrap();
    let grandchild = child.join("gc"); std::fs::create_dir_all(&grandchild).unwrap();
    let other = tmp("many-other");
    // the most specific root containing cwd wins (not the first listed)
    let mut c = Client::start(&home, &grandchild, true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&file_uri(&parent), &file_uri(&child)]);
    assert_eq!(c.bound_project(10).unwrap(), child.canonicalize().unwrap().to_string_lossy());
    // cwd is the parent of exactly one root → that root
    let mut c = Client::start(&home, &parent, true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&file_uri(&child), &file_uri(&other)]);
    assert_eq!(c.bound_project(10).unwrap(), child.canonicalize().unwrap().to_string_lossy());
    // several roots, none related to cwd → fail closed
    let mut c = Client::start(&home, &other, true);
    let req = c.roots_request().unwrap();
    c.answer_roots(&req, &[&file_uri(&child), &file_uri(&grandchild)]);
    let err = c.bound_project(10).unwrap_err();
    assert!(err.contains("none is this directory"), "{err}");
}

#[test]
fn a_late_or_failed_roots_answer_means_cwd() {
    let home = tmp("home-late");
    let proj = tmp("proj-late");
    let other = tmp("other-late");
    // error answer → cwd
    let mut c = Client::start(&home, &proj, true);
    let req = c.roots_request().unwrap();
    c.send(serde_json::json!({ "jsonrpc": "2.0", "id": req["id"].clone(), "error": { "code": -1, "message": "no" } }));
    assert_eq!(c.bound_project(10).unwrap(), proj.canonicalize().unwrap().to_string_lossy());
    // no answer at all → the first call waits briefly, then cwd; a later answer changes nothing
    let mut c = Client::start(&home, &proj, true);
    let req = c.roots_request().unwrap();
    let started = std::time::Instant::now();
    assert_eq!(c.bound_project(10).unwrap(), proj.canonicalize().unwrap().to_string_lossy());
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(1500) && waited < Duration::from_secs(8), "waited {waited:?}");
    c.answer_roots(&req, &[&file_uri(&other)]);
    assert_eq!(c.bound_project(20).unwrap(), proj.canonicalize().unwrap().to_string_lossy(), "bound once");
}
