//! The MCP server serves one directory, decided once: the client's `roots` when offered,
//! else its cwd — never a tool argument — and refuses to serve from directories that are
//! not projects (§13.1 rule 3, §13.5).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tokenstash-mcp-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Run the server in `cwd`, feed it `lines`, answer a `roots/list` request with `roots`
/// (if given), return every response line.
fn session(home: &Path, cwd: &Path, lines: &[String], roots: Option<Vec<String>>) -> Vec<serde_json::Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tokenstash"))
        .arg("mcp")
        .current_dir(cwd)
        .env("TOKENSTASH_HOME", home)
        .env("TOKENSTASH_STASH", "insecure-file")
        .env_remove("CLAUDECODE")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut out = vec![];
        for l in BufReader::new(stdout).lines() {
            let Ok(l) = l else { break };
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&l) { out.push(v); }
        }
        out
    });
    let caps = if roots.is_some() { serde_json::json!({ "roots": { "listChanged": true } }) } else { serde_json::json!({}) };
    writeln!(stdin, "{}", serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "clientInfo": { "name": "test" }, "capabilities": caps } })).unwrap();
    writeln!(stdin, "{}", serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).unwrap();
    if let Some(roots) = roots {
        // the server asks; we answer as a client would
        let list: Vec<_> = roots.iter().map(|r| serde_json::json!({ "uri": format!("file://{r}"), "name": "r" })).collect();
        writeln!(stdin, "{}", serde_json::json!({ "jsonrpc": "2.0", "id": "tokenstash-roots-1", "result": { "roots": list } })).unwrap();
    }
    for l in lines { writeln!(stdin, "{l}").unwrap(); }
    drop(stdin);
    let out = reader.join().unwrap();
    let _ = child.wait();
    out
}

fn call(id: u64, tool: &str, args: serde_json::Value) -> String {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": tool, "arguments": args } }).to_string()
}

fn text_of(v: &serde_json::Value) -> String {
    v.pointer("/result/content/0/text").and_then(|t| t.as_str()).unwrap_or("").to_string()
}

#[test]
fn refused_directories_never_serve_and_schemas_name_no_project() {
    let home = tmp("home-refused");
    for cwd in [PathBuf::from("/"), dirs::home_dir().unwrap(), PathBuf::from("/tmp")] {
        let out = session(&home, &cwd, &[call(2, "secrets_list", serde_json::json!({}))], None);
        let resp = out.iter().find(|v| v.get("id") == Some(&serde_json::json!(2))).expect("a response");
        assert_eq!(resp.pointer("/result/isError"), Some(&serde_json::json!(true)), "{cwd:?}: {resp}");
        assert!(text_of(resp).contains("no project bound"), "{cwd:?}: {}", text_of(resp));
        assert!(text_of(resp).contains("Restart your agent in the project directory"));
    }
    let proj = tmp("proj-schemas");
    let out = session(&home, &proj, &[serde_json::json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list" }).to_string()], None);
    let tools = out.iter().find(|v| v.get("id") == Some(&serde_json::json!(5))).unwrap();
    let s = tools.to_string();
    assert!(!s.contains("\"project\""), "no schema may take a project: {s}");
}

#[test]
fn the_server_serves_its_directory_and_refuses_another() {
    let home = tmp("home-bind");
    let a = tmp("proj-a");
    let b = tmp("proj-b");
    let ac = a.canonicalize().unwrap();
    // a human step filed from A lands in A's task list
    let out = session(&home, &a, &[
        call(2, "human_request", serde_json::json!({ "title": "Flip the switch" })),
        call(3, "human_request", serde_json::json!({ "title": "Other", "project": b.to_string_lossy() })),
        call(4, "task_list", serde_json::json!({})),
    ], None);
    let r2 = out.iter().find(|v| v.get("id") == Some(&serde_json::json!(2))).unwrap();
    assert_ne!(r2.pointer("/result/isError"), Some(&serde_json::json!(true)), "{r2}");
    let r3 = out.iter().find(|v| v.get("id") == Some(&serde_json::json!(3))).unwrap();
    assert!(text_of(r3).contains("does not act for"), "a request naming another directory is refused: {}", text_of(r3));
    let r4 = out.iter().find(|v| v.get("id") == Some(&serde_json::json!(4))).unwrap();
    let listed = r4.pointer("/result/structuredContent/tasks").and_then(|t| t.as_array()).cloned().unwrap_or_default();
    assert_eq!(listed.len(), 1, "{r4}");
    assert_eq!(listed[0].get("project").and_then(|p| p.as_str()), Some(ac.to_string_lossy().as_ref()));
}

#[test]
fn a_single_root_from_the_client_binds_the_server_even_when_started_elsewhere() {
    let home = tmp("home-roots");
    let proj = tmp("proj-roots");
    let projc = proj.canonicalize().unwrap();
    let elsewhere = tmp("elsewhere-roots");
    // started in `elsewhere`, but the client says the workspace is `proj`
    let out = session(&home, &elsewhere, &[
        call(2, "human_request", serde_json::json!({ "title": "Via roots" })),
        call(3, "task_list", serde_json::json!({})),
    ], Some(vec![projc.to_string_lossy().to_string()]));
    let r3 = out.iter().find(|v| v.get("id") == Some(&serde_json::json!(3))).unwrap();
    let listed = r3.pointer("/result/structuredContent/tasks").and_then(|t| t.as_array()).cloned().unwrap_or_default();
    assert_eq!(listed.len(), 1, "{r3}");
    assert_eq!(listed[0].get("project").and_then(|p| p.as_str()), Some(projc.to_string_lossy().as_ref()), "bound to the root, not the cwd");
    // a root that is refused fails closed even though the cwd would have been fine
    let out = session(&home, &proj, &[call(2, "secrets_list", serde_json::json!({}))], Some(vec![dirs::home_dir().unwrap().to_string_lossy().to_string()]));
    let r2 = out.iter().find(|v| v.get("id") == Some(&serde_json::json!(2))).unwrap();
    assert!(text_of(r2).contains("no project bound"), "{}", text_of(r2));
    // a percent-encoded root decodes
    let spaced = tmp("proj with space");
    let sc = spaced.canonicalize().unwrap();
    let enc = sc.to_string_lossy().replace(' ', "%20");
    let out = session(&home, &elsewhere, &[call(2, "human_request", serde_json::json!({ "title": "x" })), call(3, "task_list", serde_json::json!({}))], Some(vec![enc]));
    let r3 = out.iter().find(|v| v.get("id") == Some(&serde_json::json!(3))).unwrap();
    let listed = r3.pointer("/result/structuredContent/tasks").and_then(|t| t.as_array()).cloned().unwrap_or_default();
    assert_eq!(listed.first().and_then(|t| t.get("project")).and_then(|p| p.as_str()), Some(sc.to_string_lossy().as_ref()), "{r3}");
}
