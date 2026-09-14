//! `init --mode`: the mode is remembered in config and shown by `doctor`; the skill and snippet
//! for each mode can be printed without touching anything; from a pipe nothing is wired in
//! either mode (the human gate). On Linux, a pty run switches a scratch home between the two
//! modes and back out with `--undo`, the way a person at a terminal would.
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SKILL_MD: &str = include_str!("../SKILL.md");

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tokenstash-initmode-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A scratch home: no notifications, an inbox port nobody else uses, a file stash.
fn home(name: &str) -> PathBuf {
    let h = tmp(name);
    std::fs::write(h.join("config.toml"), format!("notifications = false\ninbox_port = {}\nstash_backend = \"insecure-file\"\nverify_every = \"never\"\n", free_port())).unwrap();
    h
}

fn run(home: &Path, cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tokenstash")).args(args).current_dir(cwd)
        .env("TOKENSTASH_HOME", home).env("TOKENSTASH_STASH", "insecure-file").env_remove("CLAUDECODE")
        .stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap()
}

fn out(o: &std::process::Output) -> String { String::from_utf8_lossy(&o.stdout).into_owned() }
fn err(o: &std::process::Output) -> String { String::from_utf8_lossy(&o.stderr).into_owned() }

#[test]
fn the_skill_and_snippet_print_for_each_mode_without_touching_anything() {
    let home = home("print");
    let proj = tmp("print-proj");
    let auto = run(&home, &proj, &["init", "--print-skill"]);
    assert!(auto.status.success(), "{}", err(&auto));
    assert_eq!(out(&auto), SKILL_MD);
    let explicit = run(&home, &proj, &["init", "--print-skill", "--mode", "explicit"]);
    assert!(explicit.status.success(), "{}", err(&explicit));
    let text = out(&explicit);
    assert!(text.starts_with("---\nname: tokenstash\n") && text.contains("\ndisable-model-invocation: true\n"), "{text}");
    assert!(text.contains("`/tokenstash $ARGUMENTS`") && !text.contains("secrets_request"), "{text}");
    let snippet = run(&home, &proj, &["init", "--print-snippet", "--mode", "explicit"]);
    assert!(out(&snippet).contains("do not run tokenstash unless they invoke it"), "{}", out(&snippet));
    assert!(out(&run(&home, &proj, &["init", "--print-snippet"])).contains("secrets_request"));
    assert!(!home.join("tokenstash.db").exists(), "--print-* must not set anything up");
    assert!(!proj.join("AGENTS.md").exists());
}

#[test]
fn the_mode_is_remembered_and_shown_by_doctor() {
    let home = home("remember");
    let proj = tmp("remember-proj");
    let o = run(&home, &proj, &["init", "--mode", "explicit"]);
    assert!(o.status.success(), "{}", err(&o));
    let stdout = out(&o);
    assert!(stdout.contains("agent mode: explicit"), "{stdout}");
    // From a pipe the human gate holds in this mode too: nothing outside the home is written.
    assert!(stdout.contains("Agents were not registered") && !stdout.contains("Files outside"), "{stdout}");
    let cfg = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert!(cfg.contains("agent_mode = \"explicit\""), "{cfg}");
    // A later plain `init` keeps the choice.
    let again = out(&run(&home, &proj, &["init"]));
    assert!(again.contains("agent mode: explicit"), "{again}");
    let doctor = out(&run(&home, &proj, &["doctor"]));
    assert!(doctor.contains("agent mode") && doctor.contains("explicit — agents use tokenstash only when you type /tokenstash"), "{doctor}");
    // Back to auto: the default is not written, so the file still loads in 0.2.
    let back = out(&run(&home, &proj, &["init", "--mode", "auto"]));
    assert!(back.contains("agent mode: auto"), "{back}");
    let cfg = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert!(!cfg.contains("agent_mode"), "{cfg}");
    assert!(out(&run(&home, &proj, &["doctor"])).contains("auto — agents ask tokenstash on their own"));
}

#[test]
fn an_unknown_mode_is_rejected_before_anything_runs() {
    let home = home("unknown");
    let proj = tmp("unknown-proj");
    let o = run(&home, &proj, &["init", "--mode", "sometimes"]);
    assert!(!o.status.success());
    assert!(err(&o).contains("explicit") && err(&o).contains("auto"), "{}", err(&o));
    assert!(!home.join("tokenstash.db").exists());
}

/// A person at a terminal (a pty from util-linux `script`) on a scratch $HOME with every agent
/// directory present: auto wires the servers, explicit takes them out and installs the
/// commands, `--undo` restores the user's files. Linux only: BSD `script` has other flags.
#[cfg(target_os = "linux")]
#[test]
fn a_person_switches_modes_and_undoes_on_a_scratch_home() {
    if !Command::new("script").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false) {
        eprintln!("skipped: util-linux `script` not available");
        return;
    }
    let root = tmp("pty");
    let user_home = root.join("home");
    for d in [".claude", ".codex", ".cursor", ".gemini"] { std::fs::create_dir_all(user_home.join(d)).unwrap(); }
    let codex_toml = "[mcp_servers.github]\ncommand = \"gh-mcp\"\n";
    std::fs::write(user_home.join(".codex/config.toml"), codex_toml).unwrap();
    std::fs::write(user_home.join(".codex/AGENTS.md"), "# mine\n").unwrap();
    let ts_home = home("pty-ts");
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_tokenstash"), bin.join("tokenstash")).unwrap();
    // PATH holds only the scratch binary and the system dirs; if `claude` is there, this run
    // would call the real CLI, so it is skipped rather than risked.
    let path = format!("{}:/usr/bin:/bin", bin.display());
    if Path::new("/usr/bin/claude").exists() || Path::new("/bin/claude").exists() {
        eprintln!("skipped: a `claude` binary is on the system PATH");
        return;
    }
    let proj = tmp("pty-proj");
    let person = |args: &str| -> String {
        let o = Command::new("script").args(["-qec", &format!("tokenstash {args}"), "/dev/null"])
            .current_dir(&proj).env_clear()
            .env("HOME", &user_home).env("PATH", &path).env("XDG_CONFIG_HOME", user_home.join(".config"))
            .env("TOKENSTASH_HOME", &ts_home).env("TOKENSTASH_STASH", "insecure-file")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).output().unwrap();
        assert!(o.status.success(), "tokenstash {args}: {}{}", out(&o), err(&o));
        out(&o)
    };
    let read = |p: &str| std::fs::read_to_string(user_home.join(p)).unwrap_or_default();

    let auto = person("init");
    assert!(auto.contains("agent mode: auto") && auto.contains("MCP server registered") && auto.contains("Files outside"), "{auto}");
    assert!(read(".codex/config.toml").contains("[mcp_servers.tokenstash]") && read(".codex/AGENTS.md").contains("<!-- tokenstash -->"));
    assert_eq!(read(".claude/skills/tokenstash/SKILL.md"), SKILL_MD);

    let explicit = person("init --mode explicit");
    assert!(explicit.contains("MCP server removed from") && explicit.contains("/prompts:tokenstash installed") && explicit.contains("Restart any open agent session"), "{explicit}");
    assert_eq!(read(".codex/config.toml"), codex_toml, "only the tokenstash entry leaves");
    assert_eq!(read(".codex/AGENTS.md"), "# mine\n");
    assert!(read(".claude/skills/tokenstash/SKILL.md").contains("disable-model-invocation: true"));
    assert!(read(".cursor/skills/tokenstash/SKILL.md").contains("disable-model-invocation: true"));
    assert!(read(".codex/prompts/tokenstash.md").contains("$ARGUMENTS") && read(".gemini/commands/tokenstash.toml").contains("{{args}}"));
    assert!(!user_home.join(".claude.json").exists() && !user_home.join(".gemini/settings.json").exists(), "files init created for the server alone are gone");
    let doctor = person("doctor");
    assert!(doctor.contains("claude-code (skill: explicit), codex (prompt), cursor (skill: explicit), gemini-cli (command)"), "{doctor}");

    let undo = person("init --undo");
    assert!(undo.contains("restored") || undo.contains("removed"), "{undo}");
    assert_eq!(read(".codex/config.toml"), codex_toml);
    assert_eq!(read(".codex/AGENTS.md"), "# mine\n");
    for gone in [".claude/skills/tokenstash", ".cursor/skills/tokenstash", ".codex/prompts/tokenstash.md", ".gemini/commands/tokenstash.toml", ".cursor/mcp.json"] {
        assert!(!user_home.join(gone).exists(), "{gone} should be gone");
    }
    assert!(person("doctor").contains("none configured"));
}
