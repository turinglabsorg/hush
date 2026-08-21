use serde::Serialize;

use crate::config::Config;
use crate::paths::Paths;
use crate::signal::find_signal_cli;
use crate::vault::Vault;

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub home: String,
    pub initialized: bool,
    pub identity: bool,
    pub secrets: usize,
    pub signal_cli: Option<String>,
    pub signal_account: Option<String>,
    pub allow_from: Vec<String>,
    pub ok: bool,
    pub issues: Vec<String>,
}

pub fn report(paths: &Paths) -> DoctorReport {
    let mut issues = Vec::new();
    let identity = paths.identity_file().exists();
    let config = Config::load(paths).ok();
    let initialized = identity && config.is_some();
    if !initialized {
        issues.push("run `hush init` then `hush signal link`".into());
    }
    let secrets = Vault::open(paths)
        .ok()
        .and_then(|vault| vault.list().ok())
        .map(|items| items.len())
        .unwrap_or(0);
    let signal_cli = find_signal_cli().map(|path| path.display().to_string());
    if signal_cli.is_none() {
        issues.push("install signal-cli or set HUSH_SIGNAL_CLI".into());
    }
    let signal_account = config.as_ref().and_then(|cfg| cfg.signal.account.clone());
    if initialized && signal_account.is_none() {
        issues.push("run `hush signal link` and scan the QR from Signal on your phone".into());
    }
    let allow_from = config
        .as_ref()
        .map(|cfg| cfg.signal.allow_from.clone())
        .unwrap_or_default();
    DoctorReport {
        home: paths.root().display().to_string(),
        initialized,
        identity,
        secrets,
        signal_cli,
        signal_account,
        allow_from,
        ok: issues.is_empty(),
        issues,
    }
}
