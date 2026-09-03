use std::fs;
use std::path::{Path, PathBuf};

use crate::Error;

/// Marker identifying a file as a hush-generated shim.
pub const SHIM_MARKER: &str = "hush agent shim";

/// A `bw` blocker for agent sandboxes. The agent must never invoke the real
/// Bitwarden CLI directly (`bw get`, `bw send receive`, ... print secrets to
/// stdout, i.e. into the transcript). Install this script as `bw` in a
/// directory placed FIRST in the agent's PATH; every direct call then fails
/// with a pointer back to hush. The human keeps using the real `bw` via
/// absolute path or a separate PATH, and hush itself via `HUSH_BW_BIN`.
pub const SHIM_SCRIPT: &str = r#"#!/bin/sh
# hush agent shim: direct `bw` access is blocked in agent sandboxes.
# Secrets must only flow through hush (`hush pull`, `hush run --redact`).
echo "hush: blocked: direct 'bw' access would print secrets to the transcript" >&2
echo "hush: use 'hush pull --name NAME [--send URL]' and 'hush run --name NAME --env VAR --redact -- <cmd>' instead" >&2
exit 126
"#;

pub fn is_shim(path: &Path) -> bool {
    fs::read_to_string(path)
        .map(|content| content.contains(SHIM_MARKER))
        .unwrap_or(false)
}

pub fn install_shim(dir: &Path, force: bool) -> Result<PathBuf, Error> {
    fs::create_dir_all(dir)?;
    let path = dir.join("bw");
    if path.exists() && !is_shim(&path) && !force {
        return Err(Error::user(format!(
            "refusing to overwrite non-shim file {}; use --force",
            path.display()
        )));
    }
    fs::write(&path, SHIM_SCRIPT)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn installs_executable_shim() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("bin");
        let path = install_shim(&target, false).unwrap();
        assert_eq!(path, target.join("bw"));
        assert!(is_shim(&path));
    }

    #[test]
    fn refuses_to_clobber_real_binary() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("bw"), "real binary").unwrap();
        assert!(install_shim(dir.path(), false).is_err());
        assert!(install_shim(dir.path(), true).is_ok());
        assert!(is_shim(&dir.path().join("bw")));
    }
}
