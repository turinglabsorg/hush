use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BwStatus {
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub user_email: Option<String>,
    #[serde(rename = "status", default = "unauthenticated")]
    pub state: String,
    #[serde(default)]
    pub last_sync: Option<String>,
}

fn unauthenticated() -> String {
    "unauthenticated".into()
}

impl BwStatus {
    pub fn unlocked(&self) -> bool {
        self.state.eq_ignore_ascii_case("unlocked")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultItem {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub login: Option<ItemLogin>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemLogin {
    #[serde(default)]
    pub password: Option<String>,
}

pub fn find_bw() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("HUSH_BW_BIN") {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
        return None;
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("bw");
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = dir.join("bw.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

pub fn require_bw() -> Result<PathBuf, Error> {
    find_bw().ok_or(Error::BwMissing)
}

fn run_bw(args: &[&str]) -> Result<String, Error> {
    let bw = require_bw()?;
    run_bw_at(&bw, args)
}

fn run_bw_at(bw: &Path, args: &[&str]) -> Result<String, Error> {
    let output = Command::new(bw)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        return Err(Error::user(format!(
            "bw {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn status() -> Result<BwStatus, Error> {
    let out = run_bw(&["status"])?;
    let mut parsed: BwStatus =
        serde_json::from_str(&out).map_err(|_| Error::user("bw status returned invalid JSON"))?;
    if parsed.state.is_empty() {
        parsed.state = unauthenticated();
    }
    Ok(parsed)
}

pub fn require_unlocked() -> Result<BwStatus, Error> {
    let st = status()?;
    if st.unlocked() {
        Ok(st)
    } else {
        Err(Error::NotLoggedIn)
    }
}

pub fn sync() -> Result<(), Error> {
    require_unlocked()?;
    run_bw(&["sync"])?;
    Ok(())
}

/// Receive a Bitwarden Send by URL. Works without an unlocked vault;
/// the URL itself is not secret, the Send content is.
pub fn send_receive(url: &str, password_args: &[String]) -> Result<Vec<u8>, Error> {
    let bw = require_bw()?;
    let mut args: Vec<&str> = vec!["send", "receive", url];
    let mut owned: Vec<String> = Vec::new();
    for flag in password_args {
        owned.push(flag.clone());
    }
    let mut refs: Vec<&str> = args.clone();
    for flag in &owned {
        refs.push(flag.as_str());
    }
    args = refs;
    let output = Command::new(&bw)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        return Err(Error::user(format!(
            "bw send receive failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

pub fn list_items(search: Option<&str>) -> Result<Vec<VaultItem>, Error> {
    let mut args: Vec<&str> = vec!["list", "items"];
    let search_owned;
    if let Some(term) = search {
        search_owned = term.to_string();
        args.push("--search");
        args.push(&search_owned);
    }
    let out = run_bw(&args)?;
    let items: Vec<VaultItem> = serde_json::from_str(&out)
        .map_err(|_| Error::user("bw list items returned invalid JSON"))?;
    Ok(items)
}

pub fn get_item(query: &str) -> Result<VaultItem, Error> {
    let out = run_bw(&["get", "item", query]).map_err(|err| match err {
        Error::User(msg) if msg.to_ascii_lowercase().contains("not found") => {
            Error::NotFound(query.to_string())
        }
        other => other,
    })?;
    serde_json::from_str(&out).map_err(|_| Error::user("bw get item returned invalid JSON"))
}

pub fn delete_item(id: &str) -> Result<(), Error> {
    run_bw(&["delete", "item", id])?;
    Ok(())
}

/// Extract the secret bytes from a vault item: login password first,
/// then secure-note notes. Never logs the value.
pub fn item_secret(item: &VaultItem) -> Result<Vec<u8>, Error> {
    if let Some(login) = &item.login {
        if let Some(password) = &login.password {
            if !password.is_empty() {
                return Ok(password.as_bytes().to_vec());
            }
        }
    }
    if let Some(notes) = &item.notes {
        if !notes.trim().is_empty() {
            let mut value = notes.as_bytes().to_vec();
            while value.last() == Some(&b'\n') || value.last() == Some(&b'\r') {
                value.pop();
            }
            return Ok(value);
        }
    }
    Err(Error::user(format!(
        "vault item `{}` has no password or notes to store",
        item.name
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bw_status() {
        let st: BwStatus = serde_json::from_str(
            r#"{"serverUrl":"https://vault.bitwarden.com","lastSync":"2026-01-01","userEmail":"agent@example.com","userId":"abc","status":"unlocked"}"#,
        )
        .unwrap();
        assert!(st.unlocked());
        assert_eq!(st.user_email.as_deref(), Some("agent@example.com"));
        let locked: BwStatus = serde_json::from_str(r#"{"status":"locked"}"#).unwrap();
        assert!(!locked.unlocked());
    }

    #[test]
    fn prefers_password_over_notes() {
        let item = VaultItem {
            id: "1".into(),
            name: "x".into(),
            login: Some(ItemLogin {
                password: Some("pw-secret".into()),
            }),
            notes: Some("notes-secret".into()),
        };
        assert_eq!(&item_secret(&item).unwrap()[..], b"pw-secret");
    }

    #[test]
    fn falls_back_to_notes_and_trims() {
        let item = VaultItem {
            id: "1".into(),
            name: "x".into(),
            login: None,
            notes: Some("note-secret\n".into()),
        };
        assert_eq!(&item_secret(&item).unwrap()[..], b"note-secret");
    }

    #[test]
    fn rejects_empty_item() {
        let item = VaultItem {
            id: "1".into(),
            name: "x".into(),
            login: None,
            notes: None,
        };
        assert!(item_secret(&item).is_err());
    }
}
