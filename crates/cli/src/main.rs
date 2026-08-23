//! tokenstash — Your agent asks you for a key once. Never again.

mod cmd;
mod notify;
mod util;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tokenstash", version, about = "Your agent asks you for a key once. Never again — in any project, in any agent.")]
#[command(long_about = "Agents run `tokenstash need NAME`. If the key is in your stash it is written to the project's env file instantly.\nIf not, a task is filed for you: you acquire the key yourself (own account, own signup), paste it once, and the agent resumes.\nSecret values are never printed, never returned to the agent, never logged.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Request one or more secrets for this project (hit → inject, miss → file a task). Exit 0 injected / 10 pending / 20 denied / 30 expired.
    Need(cmd::need::NeedArgs),
    /// File a non-secret task for the human (DNS record, dashboard toggle, OAuth consent screen…).
    Ask(cmd::need::AskArgs),
    /// Answer a task from the terminal (paste a secret, approve, or mark done).
    Answer(cmd::answer::AnswerArgs),
    /// List open tasks for this project (--all for every project).
    Tasks(cmd::admin::TasksArgs),
    /// List stashed secret names and identities. Never values.
    List(cmd::admin::ListArgs),
    /// Delete a secret from the stash.
    Forget(cmd::admin::ForgetArgs),
    /// Bind a secret name to an identity for this project (work vs personal).
    Bind(cmd::admin::BindArgs),
    /// Manage trust roots (directories whose projects get silent injection).
    Trust(cmd::admin::TrustArgs),
    /// Show recent audit events (never values).
    Audit(cmd::admin::AuditArgs),
    /// Detect agents, write MCP config + skill file, choose a stash backend, set trust roots.
    Init(cmd::init::InitArgs),
    /// Check that everything works.
    Doctor,
    /// Run a command with the project's env file loaded; if it dies on a missing key, file the task, wait, inject, restart.
    Run(cmd::run::RunArgs),
    /// Serve the MCP server over stdio (used by agents; configured by `init`).
    Mcp,
    /// Serve the localhost inbox (started automatically when a task is filed).
    Inbox(cmd::inbox::InboxArgs),
    /// Open the inbox in your browser.
    Open,
    /// Print the provider registry (names and signup URLs).
    Registry,
}

fn main() {
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tokenstash: error: {e:#}");
            tokenstash_core::exit::ERROR
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<i32> {
    match cli.cmd {
        Cmd::Need(a) => cmd::need::need(a),
        Cmd::Ask(a) => cmd::need::ask(a),
        Cmd::Answer(a) => cmd::answer::answer(a),
        Cmd::Tasks(a) => cmd::admin::tasks(a),
        Cmd::List(a) => cmd::admin::list(a),
        Cmd::Forget(a) => cmd::admin::forget(a),
        Cmd::Bind(a) => cmd::admin::bind(a),
        Cmd::Trust(a) => cmd::admin::trust(a),
        Cmd::Audit(a) => cmd::admin::audit(a),
        Cmd::Init(a) => cmd::init::init(a),
        Cmd::Doctor => cmd::doctor::doctor(),
        Cmd::Run(a) => cmd::run::run(a),
        Cmd::Mcp => cmd::mcp::serve(),
        Cmd::Inbox(a) => cmd::inbox::serve(a),
        Cmd::Open => {
            let cfg = tokenstash_core::Config::load()?;
            let url = util::inbox_url(&cfg, None);
            notify::ensure_inbox(&cfg);
            let _ = open::that(&url);
            println!("{url}");
            Ok(0)
        }
        Cmd::Registry => {
            for p in tokenstash_core::registry::all() {
                println!("{:<36} {:<22} {}{}", p.name, p.provider, p.url, if p.sensitive { "  [sensitive]" } else { "" });
            }
            println!("\n{} providers. Add more: registry/providers.json", tokenstash_core::registry::count());
            Ok(0)
        }
    }
}
