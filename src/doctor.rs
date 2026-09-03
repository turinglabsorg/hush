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
    pub bw_shim: bool,
    pub bitwarden_state: Option<String>,
    pub session: bool,
    pub ok: bool,
    pub issues: Vec<String>,
}

pub fn report(paths: &Paths) -> DoctorReport {
    use crate::bitwarden::{find_bw, status};
    use crate::shim::is_shim;

    let mut issues = Vec::new();
    let identity = paths.identity_file().exists();
    let initialized = identity && Config::load(paths).is_ok();
    if !initialized {
        issues.push("run `hush init`".into());
    }
    check_private(paths.root(), 0o700, "hush home", &mut issues);
    check_private(&paths.vault_dir(), 0o700, "vault dir", &mut issues);
    if identity {
        check_private(&paths.identity_file(), 0o600, "identity file", &mut issues);
    }
    let secrets = Vault::open(paths)
        .ok()
        .and_then(|vault| vault.list().ok())
        .map(|items| items.len())
        .unwrap_or(0);
    let bw = find_bw().map(|path| path.display().to_string());
    let bw_shim = find_bw().map(|path| is_shim(&path)).unwrap_or(false);
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
        bw_shim,
        bitwarden_state,
        session,
        ok: issues.is_empty(),
        issues,
    }
}

/// The age identity is the keys to every secret: it must never be readable
/// by anyone but the owner. Same-user agents bypass file permissions, which
/// is why the sandbox guide requires a dedicated agent user (phase 2), but
/// loose modes are always a bug — fail loudly here.
fn check_private(path: &std::path::Path, expected: u32, label: &str, issues: &mut Vec<String>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(md) => {
                let mode = md.permissions().mode() & 0o777;
                if mode != expected {
                    issues.push(format!(
                        "{label} ({}) has mode {mode:o}, expected {expected:o}; fix with `chmod`",
                        path.display()
                    ));
                }
            }
            Err(_) => {
                // Existence is reported by the other checks; nothing to add.
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, expected, label, issues);
    }
}
