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

/// $HOME and the config root are scratch too: `init` keeps its undo record under the fixed
/// config dir and `doctor` reads the agents' files under $HOME, and neither may be the
/// developer's.
fn run(home: &Path, cwd: &Path, args: &[&str]) -> std::process::Output {
    let user_home = home.join("user-home");
    std::fs::create_dir_all(&user_home).unwrap();
    Command::new(env!("CARGO_BIN_EXE_tokenstash")).args(args).current_dir(cwd)
        .env("HOME", &user_home).env("XDG_CONFIG_HOME", user_home.join(".config"))
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
    assert!(text.contains(&format!("TOKENSTASH_HOME={}", home.display())), "the skill names this shell's home: {text}");
    let snippet = run(&home, &proj, &["init", "--print-snippet", "--mode", "explicit"]);
    assert!(out(&snippet).contains("Do not run tokenstash until the user invokes"), "{}", out(&snippet));
    assert!(out(&run(&home, &proj, &["init", "--print-snippet"])).contains("secrets_request"));
    assert!(!home.join("tokenstash.db").exists(), "--print-* must not set anything up");
    assert!(!proj.join("AGENTS.md").exists());
    // Without --mode, printing follows the mode remembered for this machine.
    std::fs::write(home.join("config.toml"), format!("{}agent_mode = \"explicit\"\n", std::fs::read_to_string(home.join("config.toml")).unwrap())).unwrap();
    assert!(out(&run(&home, &proj, &["init", "--print-skill"])).contains("disable-model-invocation: true"));
    assert!(out(&run(&home, &proj, &["init", "--print-snippet"])).contains("Do not run tokenstash until the user invokes"));
    assert!(!out(&run(&home, &proj, &["init", "--print-skill", "--mode", "auto"])).contains("disable-model-invocation"));
}

/// Astra: an agent with a shell must not be able to choose the mode (it could put automatic
/// mode back), write a project's instructions, or undo (which restores wiring explicit mode
/// took out). From a pipe all three refuse, before anything is written.
#[test]
fn choosing_the_mode_writing_a_project_and_undo_are_for_a_person() {
    let home = home("gates");
    let proj = tmp("gates-proj");
    std::fs::write(home.join("config.toml"), format!("{}agent_mode = \"explicit\"\n", std::fs::read_to_string(home.join("config.toml")).unwrap())).unwrap();
    for args in [vec!["init", "--mode", "auto"], vec!["init", "--mode", "explicit"], vec!["init", "--project"], vec!["init", "--undo"], vec!["init", "--mode", "auto", "--no-agents"]] {
        let o = run(&home, &proj, &args);
        assert!(!o.status.success(), "{args:?} must refuse: {}", out(&o));
        assert!(err(&o).contains("for a person at a terminal"), "{args:?}: {}", err(&o));
        assert!(out(&o).trim().is_empty(), "{args:?} printed to a pipe: {}", out(&o));
    }
    assert!(std::fs::read_to_string(home.join("config.toml")).unwrap().contains("agent_mode = \"explicit\""), "the person's choice stands");
    assert!(!home.join("tokenstash.db").exists() && !proj.join("AGENTS.md").exists());
    // A plain `init` still sets the stash up for anyone, in the mode the person chose.
    let o = run(&home, &proj, &["init"]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("agent mode: explicit") && out(&o).contains("Agents were not registered"), "{}", out(&o));
    assert!(out(&run(&home, &proj, &["doctor"])).contains("explicit — agents use tokenstash only when you type /tokenstash"));
}

#[test]
fn an_unknown_mode_is_rejected_before_anything_runs() {
    let home = home("unknown");
    let proj = tmp("unknown-proj");
    let o = run(&home, &proj, &["init", "--mode", "sometimes"]);
    assert!(!o.status.success());
    assert!(err(&o).contains("explicit") && err(&o).contains("auto") && !err(&o).contains("for a person"), "{}", err(&o));
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
    assert!(std::fs::read_to_string(ts_home.join("config.toml")).unwrap().contains("agent_mode = \"explicit\""));
    // A later plain `init` keeps the choice.
    assert!(person("init").contains("agent mode: explicit"));
    assert_eq!(read(".codex/config.toml"), codex_toml, "only the tokenstash entry leaves");
    assert_eq!(read(".codex/AGENTS.md"), "# mine\n");
    assert!(read(".claude/skills/tokenstash/SKILL.md").contains("disable-model-invocation: true"));
    assert!(read(".cursor/skills/tokenstash/SKILL.md").contains("disable-model-invocation: true"));
    assert!(read(".codex/prompts/tokenstash.md").contains("$ARGUMENTS") && read(".gemini/commands/tokenstash.toml").contains("{{args}}"));
    assert!(!user_home.join(".claude.json").exists() && !user_home.join(".gemini/settings.json").exists(), "files init created for the server alone are gone");
    let doctor = person("doctor");
    assert!(doctor.contains("explicit — agents use tokenstash only when you type /tokenstash"), "{doctor}");
    assert!(doctor.contains("claude-code (skill: explicit), codex (prompt), cursor (skill: explicit), gemini-cli (command)"), "{doctor}");
    // Back to auto and the default is not written, so the file still loads in 0.2.
    assert!(person("init --mode auto").contains("agent mode: auto"));
    assert!(!std::fs::read_to_string(ts_home.join("config.toml")).unwrap().contains("agent_mode"));
    assert!(person("init --mode explicit").contains("/prompts:tokenstash installed"));

    // Config files back to what init found carry no whole-file record, so an edit made now
    // survives undo; the auto→explicit→auto skill file is put back exactly.
    std::fs::write(user_home.join(".codex/config.toml"), format!("{codex_toml}\n[mcp_servers.linear]\ncommand = \"linear-mcp\"\n")).unwrap();
    let undo = person("init --undo");
    assert!(undo.contains("restored") || undo.contains("removed"), "{undo}");
    assert!(read(".codex/config.toml").contains("linear-mcp") && read(".codex/config.toml").contains("gh-mcp"), "{}", read(".codex/config.toml"));
    assert_eq!(read(".codex/AGENTS.md"), "# mine\n");
    for gone in [".claude/skills/tokenstash", ".cursor/skills/tokenstash", ".codex/prompts/tokenstash.md", ".gemini/commands/tokenstash.toml", ".cursor/mcp.json"] {
        assert!(!user_home.join(gone).exists(), "{gone} should be gone");
    }
    assert!(person("doctor").contains("none configured"));
}
