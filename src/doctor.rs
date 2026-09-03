use serde::Serialize;

use crate::config::Config;
use crate::paths::Paths;
use crate::vault::Vault;

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub home: String,
    pub initialized: bool,
    pub identity: bool,
    pub secrets: usize,
    pub bw: Option<String>,
    pub bitwarden_state: Option<String>,
    pub session: bool,
    pub ok: bool,
    pub issues: Vec<String>,
}

pub fn report(paths: &Paths) -> DoctorReport {
    use crate::bitwarden::{find_bw, status};

    let mut issues = Vec::new();
    let identity = paths.identity_file().exists();
    let initialized = identity && Config::load(paths).is_ok();
    if !initialized {
        issues.push("run `hush init`".into());
    }
    let secrets = Vault::open(paths)
        .ok()
        .and_then(|vault| vault.list().ok())
        .map(|items| items.len())
        .unwrap_or(0);
    let bw = find_bw().map(|path| path.display().to_string());
    if bw.is_none() {
        issues.push("install the Bitwarden CLI (`bw`) or set HUSH_BW_BIN".into());
    }
    let bitwarden_state = status().ok().map(|st| st.state.clone());
    match bitwarden_state.as_deref() {
        Some("unlocked") => {}
        Some("locked") => {
            issues.push("vault is locked; run `bw unlock` and export BW_SESSION".into())
        }
        _ => issues.push("run `bw login` then `bw unlock` and export BW_SESSION".into()),
    }
    let session = std::env::var_os("BW_SESSION").is_some();
    DoctorReport {
        home: paths.root().display().to_string(),
        initialized,
        identity,
        secrets,
        bw,
        bitwarden_state,
        session,
        ok: issues.is_empty(),
        issues,
    }
}
