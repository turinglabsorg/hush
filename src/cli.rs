use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::doctor;
use crate::paths::Paths;
use crate::signal;
use crate::vault::{Meta, Vault};
use crate::Error;

#[derive(Parser)]
#[command(
    name = "hush",
    version,
    about = "Agent-blind secrets: ingest over Signal, use by name"
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
    /// Inject a secret into a child process environment and exec it
    Run {
        #[arg(long)]
        name: String,
        #[arg(long)]
        env: String,
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
    /// Delete a secret by name
    Rm { name: String },
    /// Keep receiving Signal deposits (human daemon)
    Listen {
        #[arg(long)]
        json: bool,
    },
    /// Fetch waiting Signal messages and store them (agent-facing)
    #[command(alias = "recv")]
    Pull {
        /// Name to store. Use this when the Signal message is the raw secret.
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        json: bool,
        /// Seconds to wait for Signal (signal-cli receive timeout)
        #[arg(long, default_value_t = 8)]
        timeout: u64,
    },
    /// Signal device and allowlist
    #[command(subcommand)]
    Signal(SignalCmd),
    /// Check local setup
    Doctor {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SignalCmd {
    /// Link hush as a Signal secondary device (scan the QR from your phone)
    Link {
        #[arg(long, default_value = "hush")]
        name: String,
    },
    /// Record the Signal account number if link did not detect it
    Account { number: String },
    /// Allow another Signal sender to deposit secrets
    Allow { id: String },
    /// Show Signal link status
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
        Cmd::Run { name, env, command } => crate::run::run(&paths, &name, &env, &command),
        Cmd::Rm { name } => rm(&paths, &name),
        Cmd::Listen { json } => crate::listen::listen(&paths, json),
        Cmd::Pull {
            name,
            json,
            timeout,
        } => crate::pull::pull(&paths, name.as_deref(), json, timeout),
        Cmd::Signal(SignalCmd::Link { name }) => signal_link(&paths, &name),
        Cmd::Signal(SignalCmd::Account { number }) => signal_account(&paths, &number),
        Cmd::Signal(SignalCmd::Allow { id }) => signal_allow(&paths, &id),
        Cmd::Signal(SignalCmd::Status { json }) => signal_status(&paths, json),
        Cmd::Doctor { json } => doctor_cmd(&paths, json),
    }
}

fn init(paths: &Paths) -> Result<(), Error> {
    Vault::init(paths)?;
    Config::default().save(paths)?;
    println!("initialized {}", paths.root().display());
    println!("next: hush signal link");
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

fn signal_link(paths: &Paths, device_name: &str) -> Result<(), Error> {
    let mut config = Config::load(paths)?;
    let signal_cli = signal::require_signal_cli()?;
    config.signal.device_name = device_name.to_string();
    eprintln!("scan this QR in Signal: Settings → Linked devices");
    let account = signal::link_device(&signal_cli, device_name)?;
    if let Some(account) = account {
        config.signal.account = Some(account.clone());
        config.save(paths)?;
        println!("linked as {account}");
    } else {
        config.save(paths)?;
        println!("device linked; if the account number is missing run `hush signal account +E164`");
    }
    println!("next: send the secret to Signal Note to Self, then:");
    println!("  hush pull --name NAME --json");
    Ok(())
}

fn signal_account(paths: &Paths, number: &str) -> Result<(), Error> {
    let mut config = Config::load(paths)?;
    let number = number.trim();
    if !number.starts_with('+') {
        return Err(Error::user("account must be E.164 (start with +)"));
    }
    config.signal.account = Some(number.to_string());
    config.save(paths)?;
    println!("signal account {number}");
    Ok(())
}

fn signal_allow(paths: &Paths, id: &str) -> Result<(), Error> {
    let mut config = Config::load(paths)?;
    config.allow(id);
    config.save(paths)?;
    println!("allow_from {:?}", config.signal.allow_from);
    Ok(())
}

fn signal_status(paths: &Paths, _json: bool) -> Result<(), Error> {
    let config = Config::load(paths)?;
    let payload = serde_json::json!({
        "account": config.signal.account,
        "device_name": config.signal.device_name,
        "allow_from": config.signal.allow_from,
        "socket": config.signal.socket,
        "signal_cli": signal::find_signal_cli().map(|p| p.display().to_string()),
    });
    println!("{payload}");
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
        println!(
            "signal-cli: {}",
            report.signal_cli.as_deref().unwrap_or("missing")
        );
        println!(
            "signal account: {}",
            report.signal_account.as_deref().unwrap_or("unlinked")
        );
        println!("allow_from: {:?}", report.allow_from);
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
