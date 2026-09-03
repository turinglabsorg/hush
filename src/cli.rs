use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use crate::bitwarden;
use crate::config::Config;
use crate::doctor;
use crate::paths::Paths;
use crate::pull::{pull, PullOptions};
use crate::vault::{Meta, Vault};
use crate::Error;

#[derive(Parser)]
#[command(
    name = "hush",
    version,
    about = "Agent-blind secrets: ingest over Bitwarden, use by name"
)]
struct Cli {
    #[arg(long, global = true, env = "HUSH_HOME")]
    home: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create ~/.hush and an age identity
    Init,
    /// List stored secret names (never values)
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show metadata for a secret (never the value)
    Info {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Inject a secret into a child process environment and exec it.
    /// Secret-bearing env vars (BW_SESSION, ...) are never inherited.
    Run {
        #[arg(long)]
        name: String,
        #[arg(long)]
        env: String,
        /// Pipe child output and replace the secret with [redacted by hush]
        #[arg(long)]
        redact: bool,
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
    /// Delete a secret by name
    Rm { name: String },
    /// Keep polling the Bitwarden vault for `hush put NAME` items (human daemon)
    Listen {
        #[arg(long)]
        json: bool,
        /// Seconds between vault polls (minimum 5)
        #[arg(long, default_value_t = 30)]
        interval: u64,
        /// Trash vault items after they are stored
        #[arg(long)]
        consume: bool,
    },
    /// Fetch a secret from Bitwarden and store it (agent-facing)
    Pull {
        /// Name to store. With `--send URL` this is required; otherwise the
        /// agent vault is searched for an item or `hush put NAME` entry.
        #[arg(long)]
        name: Option<String>,
        /// Receive a Bitwarden Send by URL (the URL is not secret)
        #[arg(long)]
        send: Option<String>,
        /// Env var holding the Send password (passed through to `bw`)
        #[arg(long)]
        passwordenv: Option<String>,
        /// File holding the Send password on its first line (passed to `bw`)
        #[arg(long)]
        passwordfile: Option<String>,
        /// Email for Sends restricted to an address (drives bw verification)
        #[arg(long)]
        email: Option<String>,
        /// Shell command printing ONLY a fresh verification code (polled)
        #[arg(long)]
        code_cmd: Option<String>,
        /// Env var holding a fresh verification code
        #[arg(long)]
        codeenv: Option<String>,
        /// File holding a fresh verification code
        #[arg(long)]
        codefile: Option<String>,
        /// Overall timeout (secs) for a gated receive, incl. the code email
        #[arg(long, default_value_t = 300)]
        code_timeout: u64,
        /// Poll interval (secs) for --code-cmd
        #[arg(long, default_value_t = 10)]
        code_poll: u64,
        /// Trash the vault item after it is stored
        #[arg(long)]
        consume: bool,
        #[arg(long)]
        json: bool,
    },
    /// Bitwarden CLI status
    #[command(subcommand)]
    Bitwarden(BitwardenCmd),
    /// Install a `bw` blocker shim for agent sandboxes (human setup)
    AgentShim {
        /// Directory to install the shim into (put it first in the agent PATH)
        #[arg(long)]
        dir: PathBuf,
        /// Overwrite an existing non-shim file
        #[arg(long)]
        force: bool,
    },
    /// Check local setup
    Doctor {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum BitwardenCmd {
    /// Show Bitwarden login/unlock status (never secrets)
    Status {
        #[arg(long)]
        json: bool,
    },
}

pub fn run() -> Result<(), Error> {
    let cli = Cli::parse();
    let paths = match cli.home {
        Some(home) => Paths::new(home),
        None => Paths::from_env(),
    };
    match cli.cmd {
        Cmd::Init => init(&paths),
        Cmd::List { json } => list(&paths, json),
        Cmd::Info { name, json } => info(&paths, &name, json),
        Cmd::Run {
            name,
            env,
            redact,
            command,
        } => crate::run::run(&paths, &name, &env, &command, redact),
        Cmd::Rm { name } => rm(&paths, &name),
        Cmd::Listen {
            json,
            interval,
            consume,
        } => crate::listen::listen(&paths, json, interval, consume),
        Cmd::Pull {
            name,
            send,
            passwordenv,
            passwordfile,
            email,
            code_cmd,
            codeenv,
            codefile,
            code_timeout,
            code_poll,
            consume,
            json,
        } => {
            let mut send_auth = Vec::new();
            if let Some(var) = passwordenv {
                send_auth.push("--passwordenv".to_string());
                send_auth.push(var);
            }
            if let Some(file) = passwordfile {
                send_auth.push("--passwordfile".to_string());
                send_auth.push(file);
            }
            pull(
                &paths,
                &PullOptions {
                    name,
                    send_url: send,
                    send_auth,
                    send_email: email,
                    code_cmd,
                    code_env: codeenv,
                    code_file: codefile,
                    code_timeout_secs: code_timeout,
                    code_poll_secs: code_poll,
                    consume,
                    json,
                },
            )
        }
        Cmd::Bitwarden(BitwardenCmd::Status { json }) => bitwarden_status(json),
        Cmd::AgentShim { dir, force } => agent_shim(&dir, force),
        Cmd::Doctor { json } => doctor_cmd(&paths, json),
    }
}

fn init(paths: &Paths) -> Result<(), Error> {
    Vault::init(paths)?;
    Config::default().save(paths)?;
    println!("initialized {}", paths.root().display());
    println!("next: bw login, bw unlock, export BW_SESSION");
    Ok(())
}

fn list(paths: &Paths, json: bool) -> Result<(), Error> {
    let items = Vault::open(paths)?.list()?;
    if json {
        println!("{}", serde_json::json!({ "secrets": items }));
        return Ok(());
    }
    if items.is_empty() {
        println!("(no secrets)");
        return Ok(());
    }
    for meta in items {
        print_meta_line(&meta);
    }
    Ok(())
}

fn info(paths: &Paths, name: &str, json: bool) -> Result<(), Error> {
    let meta = Vault::open(paths)?.info(name)?;
    if json {
        println!("{}", serde_json::to_string(&meta)?);
        return Ok(());
    }
    print_meta_line(&meta);
    Ok(())
}

fn print_meta_line(meta: &Meta) {
    println!(
        "{}\tsource={}\tsender={}\tbytes={}\tupdated={}",
        meta.name, meta.source, meta.sender, meta.bytes, meta.updated
    );
}

fn rm(paths: &Paths, name: &str) -> Result<(), Error> {
    Vault::open(paths)?.remove(name)?;
    println!("removed {name}");
    Ok(())
}

fn bitwarden_status(_json: bool) -> Result<(), Error> {
    let bw = bitwarden::find_bw().map(|p| p.display().to_string());
    let payload = match bitwarden::status() {
        Ok(st) => serde_json::json!({
            "bw": bw,
            "server_url": st.server_url,
            "user_email": st.user_email,
            "state": st.state,
            "last_sync": st.last_sync,
            "session": std::env::var_os("BW_SESSION").is_some(),
        }),
        Err(err) => serde_json::json!({
            "bw": bw,
            "state": "unknown",
            "session": std::env::var_os("BW_SESSION").is_some(),
            "error": err.to_string(),
        }),
    };
    println!("{payload}");
    Ok(())
}

fn agent_shim(dir: &Path, force: bool) -> Result<(), Error> {
    let path = crate::shim::install_shim(dir, force)?;
    println!("installed bw shim: {}", path.display());
    println!("next: put {} first in the agent's PATH", dir.display());
    Ok(())
}

fn doctor_cmd(paths: &Paths, json: bool) -> Result<(), Error> {
    let report = doctor::report(paths);
    if json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("home: {}", report.home);
        println!("initialized: {}", report.initialized);
        println!("identity: {}", report.identity);
        println!("secrets: {}", report.secrets);
        println!("bw: {}", report.bw.as_deref().unwrap_or("missing"));
        println!("bw shim: {}", report.bw_shim);
        println!(
            "bitwarden: {}",
            report.bitwarden_state.as_deref().unwrap_or("unknown")
        );
        println!("session: {}", report.session);
        if report.ok {
            println!("ok");
        } else {
            for issue in &report.issues {
                writeln!(std::io::stderr(), "issue: {issue}").ok();
            }
        }
    }
    if report.ok {
        Ok(())
    } else {
        Err(Error::user("doctor found issues"))
    }
}
