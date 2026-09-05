use std::io::Write;
use std::process::{Command, Stdio};

use chrono::{Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{bitwarden, vault::Vault, Error, Paths};

#[derive(Serialize)]
pub struct SendReceipt {
    event: &'static str,
    name: String,
    pub url: String,
    expires_at: String,
    max_access_count: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Payload<'a> {
    name: &'a str,
    r#type: u8,
    text: Text<'a>,
    deletion_date: &'a str,
    expiration_date: &'a str,
    max_access_count: Option<u32>,
    disabled: bool,
    hide_email: bool,
}

#[derive(Serialize)]
struct Text<'a> {
    text: &'a str,
    hidden: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreatedSend {
    access_url: String,
}

pub fn send(
    paths: &Paths,
    name: &str,
    title: Option<&str>,
    days: u16,
    max_access_count: Option<u32>,
) -> Result<SendReceipt, Error> {
    if !(1..=31).contains(&days) || max_access_count == Some(0) {
        return Err(Error::user(
            "Send requires --days 1..31 and a positive access limit",
        ));
    }
    let title = title.unwrap_or(name);
    if title.trim().is_empty() || title.len() > 200 || title.chars().any(char::is_control) {
        return Err(Error::user(
            "Send title must contain 1..200 bytes without control characters",
        ));
    }
    let vault = Vault::open(paths)?;
    let secret = vault.get(name)?;
    let text = std::str::from_utf8(&secret)
        .map_err(|_| Error::user("Send supports UTF-8 text secrets only"))?;
    if text.is_empty() || text.chars().count() > 1000 || text.contains('\0') {
        return Err(Error::user(
            "Send supports nonempty text up to 1000 characters without NUL",
        ));
    }
    let session = match std::env::var("BW_SESSION") {
        Ok(value) if !value.is_empty() => Zeroizing::new(value.into_bytes()),
        _ => vault.get(bitwarden::DEFAULT_SESSION_SECRET)?,
    };
    let session = std::str::from_utf8(&session)
        .map_err(|_| Error::user("stored Bitwarden session is not valid UTF-8"))?;
    if session.is_empty() {
        return Err(Error::user(
            "Bitwarden session is empty; rerun `hush bitwarden unlock`",
        ));
    }
    let expiry =
        (Utc::now() + Duration::days(i64::from(days))).to_rfc3339_opts(SecondsFormat::Secs, true);
    let payload = Zeroizing::new(serde_json::to_vec(&Payload {
        name: title,
        r#type: 0,
        text: Text { text, hidden: true },
        deletion_date: &expiry,
        expiration_date: &expiry,
        max_access_count,
        disabled: false,
        hide_email: true,
    })?);
    let encoded = scoped_bw(&["encode"], session, &payload)?;
    if encoded.is_empty()
        || !encoded
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"+/=\r\n".contains(c))
    {
        return Err(Error::user(
            "Bitwarden encoding failed; no Send was created",
        ));
    }
    let output = scoped_bw(&["send", "create"], session, &encoded)?;
    let response = std::str::from_utf8(&output)
        .map_err(|_| {
            Error::user("Bitwarden Send returned an invalid receipt; inspect Sends before retrying")
        })?
        .trim();
    let receipt: Option<CreatedSend> = serde_json::from_str(response).ok();
    let url = receipt
        .as_ref()
        .map_or(response, |receipt| receipt.access_url.as_str());
    if !safe_url(url) || url.contains(text) || url.contains(session) {
        return Err(Error::user(
            "Bitwarden Send returned an invalid receipt; inspect Sends before retrying",
        ));
    }
    Ok(SendReceipt {
        event: "send-created",
        name: name.to_owned(),
        url: url.to_owned(),
        expires_at: expiry,
        max_access_count,
    })
}

fn safe_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    !authority.is_empty()
        && !authority.contains('@')
        && path.contains('#')
        && url.len() <= 2048
        && url
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b":/?#[]@!$&'()*+,;=._~%-".contains(&c))
}

fn scoped_bw(args: &[&str], session: &str, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut child = Command::new(bitwarden::require_bw()?)
        .args(args)
        .env_remove("BW_CLIENTID")
        .env_remove("BW_CLIENTSECRET")
        .env_remove("BW_PASSWORD")
        .env_remove("BW_SERVE")
        .env_remove("BW_RESPONSE")
        .env_remove("BW_PRETTY")
        .env_remove("BW_RAW")
        .env_remove("BW_QUIET")
        .env_remove("BW_CLEANEXIT")
        .env("BW_SESSION", session)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let write_result = child.stdin.take().unwrap().write_all(input);
    let output = child.wait_with_output()?;
    let stdout = Zeroizing::new(output.stdout);
    if write_result.is_err() || !output.status.success() {
        return Err(Error::user(
            "Bitwarden Send operation failed; verify the session and inspect Sends before retrying",
        ));
    }
    Ok(stdout)
}
