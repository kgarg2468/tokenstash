//! The commands that widen an agent's reach refuse when they cannot see a person: stdout is
//! a pipe here, which is what an agent's shell looks like.
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tokenstash-human-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn run(home: &PathBuf, cwd: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tokenstash")).args(args).current_dir(cwd)
        .env("TOKENSTASH_HOME", home).env("TOKENSTASH_STASH", "insecure-file").env_remove("CLAUDECODE")
        .stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap()
}

#[test]
fn widening_commands_refuse_a_pipe() {
    let home = tmp("home");
    let proj = tmp("proj");
    for args in [
        vec!["open"],
        vec!["list"],
        vec!["audit"],
        vec!["forget", "OPENAI_API_KEY"],
        vec!["tasks", "--all"],
        vec!["need", "OPENAI_API_KEY", "--force"],
    ] {
        let out = run(&home, &proj, &args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} must refuse: {err}");
        assert!(err.contains("for a person at a terminal"), "{args:?}: {err}");
        assert!(String::from_utf8_lossy(&out.stdout).trim().is_empty(), "{args:?} printed to a pipe: {}", String::from_utf8_lossy(&out.stdout));
    }
    // ...while the agent-facing ones still run.
    let out = run(&home, &proj, &["tasks", "--json"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn an_agent_cannot_answer_another_directorys_card() {
    let home = tmp("home-x");
    let theirs = tmp("theirs");
    let mine = tmp("mine");
    let out = run(&home, &theirs, &["need", "OPENAI_API_KEY"]);
    assert_eq!(out.status.code(), Some(10), "{}", String::from_utf8_lossy(&out.stderr));
    let tasks = run(&home, &theirs, &["tasks", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&tasks.stdout).unwrap();
    let id = v.as_array().unwrap()[0]["id"].as_str().unwrap().to_string();
    for (cwd, extra) in [(&mine, vec!["--stdin", "--skip-check"]), (&mine, vec!["--deny"])] {
        let mut args = vec!["answer", id.as_str()];
        args.extend(extra);
        let mut child = Command::new(env!("CARGO_BIN_EXE_tokenstash")).args(&args).current_dir(cwd)
            .env("TOKENSTASH_HOME", &home).env("TOKENSTASH_STASH", "insecure-file").env_remove("CLAUDECODE")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"sk-proj-not-mine-0123456789abcdef0123456789\n").unwrap();
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && err.contains("another directory"), "{args:?}: {err}");
    }
    let still = run(&home, &theirs, &["tasks", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&still.stdout).unwrap();
    assert_eq!(v.as_array().unwrap()[0]["status"], "pending", "nothing changed: {v}");
}
