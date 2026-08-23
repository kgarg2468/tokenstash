//! `run`: zero-config shim. Load the env file, run the command; if it fails mentioning a known
//! env var that isn't set, file the task, wait for the human, inject, and restart.
//!
//! The program's own output chooses which key gets requested, and that output may be
//! attacker-influenced. So requests that originate here are never silent: every stash hit
//! goes through an approval task ("<program> wants OPENAI_API_KEY — allow?") on every
//! invocation, regardless of earlier approvals. The human authorizes the injection, not the
//! child process. Once approved the key is in the env file, so a later run does not fail
//! on it and nothing is re-asked in normal use.

use crate::cmd::need::notify_pending;
use crate::util::{self, App};
use anyhow::{bail, Result};
use clap::Args;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokenstash_core::need::{self, NeedOpts};
use tokenstash_core::tasks::SecretRequest;

#[derive(Args)]
pub struct RunArgs {
    /// Command to run (use `--` before it).
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
    /// Max restarts after injecting a missing key.
    #[arg(long, default_value = "3")]
    pub retries: u32,
    /// Seconds to wait for the human each time.
    #[arg(long, default_value = "900")]
    pub timeout: u64,
}

pub fn run(a: RunArgs) -> Result<i32> {
    let app = App::open()?;
    let project = tokenstash_core::project::current();
    let agent = tokenstash_core::project::detect_agent();
    let env_path = project.join(&app.cfg.env_file);
    let mut attempts = 0;
    loop {
        let extra = load_env(&env_path);
        let (code, output) = spawn(&a.command, &extra)?;
        if code == 0 || attempts >= a.retries {
            return Ok(code);
        }
        let missing = find_missing(&output, &extra);
        if missing.is_empty() {
            return Ok(code);
        }
        attempts += 1;
        eprintln!("\ntokenstash: command failed and mentioned {} — asking you to approve it", missing.join(", "));
        let why = format!("`{}` exited {code} and its output named this variable", a.command.join(" "));
        let opts = NeedOpts {
            req: SecretRequest { why: Some(why), ..Default::default() },
            blocking: false,
            timeout: Duration::from_secs(a.timeout),
            require_approval: true, // program output must not authorize injection on its own
            ..Default::default()
        };
        let outcomes = need::need(&app.ctx(), &project, &agent, &missing, &opts)?;
        if outcomes.iter().any(|o| o.is_pending()) {
            notify_pending(&app, &project, &agent, &outcomes);
            eprintln!("tokenstash: waiting for you → {}", util::inbox_url(&app.cfg, None));
        }
        let outcomes = if outcomes.iter().any(|o| o.is_pending()) {
            need::need(&app.ctx(), &project, &agent, &missing, &NeedOpts { blocking: true, ..opts })?
        } else {
            outcomes
        };
        if let Some(o) = outcomes.iter().find(|o| !matches!(o, need::Outcome::Injected { .. })) {
            bail!("{} was not provided ({}); not restarting", o.name(), match o {
                need::Outcome::Denied { .. } => "denied",
                need::Outcome::Expired { .. } => "expired",
                _ => "pending",
            });
        }
        eprintln!("tokenstash: approved and injected, restarting\n");
    }
}

fn load_env(path: &std::path::Path) -> HashMap<String, String> {
    let Ok(s) = std::fs::read_to_string(path) else { return HashMap::new() };
    s.lines().filter_map(tokenstash_core::envfile::parse_line).collect()
}

/// Run, teeing output to the terminal and capturing it for diagnosis.
fn spawn(cmd: &[String], extra: &HashMap<String, String>) -> Result<(i32, String)> {
    let mut c = Command::new(&cmd[0]);
    c.args(&cmd[1..]).envs(extra).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn()?;
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let t1 = std::thread::spawn(move || tee(out, false));
    let t2 = std::thread::spawn(move || tee(err, true));
    let status = child.wait()?;
    let mut captured = t1.join().unwrap_or_default();
    captured.push_str(&t2.join().unwrap_or_default());
    Ok((status.code().unwrap_or(1), captured))
}

fn tee<R: std::io::Read>(r: R, is_err: bool) -> String {
    let mut buf = String::new();
    for line in BufReader::new(r).lines().map_while(Result::ok) {
        if is_err { let _ = writeln!(std::io::stderr(), "{line}"); } else { let _ = writeln!(std::io::stdout(), "{line}"); }
        buf.push_str(&line);
        buf.push('\n');
    }
    buf
}

/// Env-var-looking tokens in the output that are in the registry and not already set.
fn find_missing(output: &str, present: &HashMap<String, String>) -> Vec<String> {
    let re = regex::Regex::new(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b").unwrap();
    let mut v: Vec<String> = vec![];
    for cap in re.captures_iter(output) {
        let name = cap[1].to_string();
        if present.contains_key(&name) || std::env::var_os(&name).is_some() { continue; }
        if tokenstash_core::registry::lookup(&name).is_none() { continue; }
        if !v.contains(&name) { v.push(name); }
    }
    v
}
