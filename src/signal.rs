use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use serde_json::{json, Value};

use crate::config::Config;
use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub sender_number: Option<String>,
    pub sender_uuid: Option<String>,
    pub body: String,
    pub is_sync: bool,
    pub is_group: bool,
}

impl Incoming {
    pub fn sender_label(&self, account: Option<&str>) -> String {
        if self.is_self(account) {
            return "self".into();
        }
        self.sender_number
            .clone()
            .or_else(|| self.sender_uuid.clone())
            .unwrap_or_else(|| "unknown".into())
    }

    pub fn is_self(&self, account: Option<&str>) -> bool {
        if self.is_sync {
            return true;
        }
        matches!(
            (account, self.sender_number.as_deref()),
            (Some(account), Some(number)) if numbers_match(account, number)
        )
    }

    pub fn allowed(&self, allow_from: &[String], account: Option<&str>) -> bool {
        for entry in allow_from {
            if entry.eq_ignore_ascii_case("self") && self.is_self(account) {
                return true;
            }
            if self.matches_id(entry) {
                return true;
            }
        }
        false
    }

    fn matches_id(&self, id: &str) -> bool {
        let id = id.trim();
        self.sender_number
            .as_deref()
            .is_some_and(|number| numbers_match(number, id))
            || self
                .sender_uuid
                .as_deref()
                .is_some_and(|uuid| uuid.eq_ignore_ascii_case(id))
    }

    pub fn ack_recipient(&self, account: Option<&str>) -> Option<String> {
        if self.is_self(account) {
            return account
                .map(ToOwned::to_owned)
                .or_else(|| self.sender_number.clone());
        }
        self.sender_number
            .clone()
            .or_else(|| self.sender_uuid.clone())
    }
}

pub fn incoming_from_rpc(value: &Value) -> Option<Incoming> {
    if value.get("method").and_then(Value::as_str) != Some("receive") {
        return None;
    }
    let params = value.get("params")?;
    let envelope = params.get("envelope").or_else(|| {
        params
            .get("result")
            .and_then(|result| result.get("envelope"))
    })?;
    incoming_from_envelope(envelope)
}

pub fn incoming_from_value(value: &Value) -> Option<Incoming> {
    incoming_from_rpc(value)
        .or_else(|| value.get("envelope").and_then(incoming_from_envelope))
        .or_else(|| incoming_from_envelope(value))
}

pub fn incoming_list_from_stdout(stdout: &str) -> Vec<Incoming> {
    let mut out = Vec::new();
    for value in json_values(stdout) {
        collect_incoming(&value, &mut out);
    }
    out
}

fn collect_incoming(value: &Value, out: &mut Vec<Incoming>) {
    if let Some(incoming) = incoming_from_value(value) {
        out.push(incoming);
        return;
    }
    if let Some(items) = value.as_array() {
        for item in items {
            collect_incoming(item, out);
        }
    }
}

fn json_values(stdout: &str) -> Vec<Value> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut values = Vec::new();
    let stream = serde_json::Deserializer::from_str(trimmed).into_iter::<Value>();
    for item in stream {
        match item {
            Ok(value) => values.push(value),
            Err(_) => break,
        }
    }
    if values.is_empty() {
        for line in trimmed.lines() {
            let line = line.trim();
            if let Ok(value) = serde_json::from_str::<Value>(line) {
                values.push(value);
            }
        }
    }
    values
}

pub fn incoming_from_envelope(envelope: &Value) -> Option<Incoming> {
    let sender_number =
        string_field(envelope, "sourceNumber").or_else(|| string_field(envelope, "source"));
    let sender_uuid = string_field(envelope, "sourceUuid");

    if let Some(data) = envelope.get("dataMessage") {
        let body = string_field(data, "message")?;
        return Some(Incoming {
            sender_number,
            sender_uuid,
            body,
            is_sync: false,
            is_group: data.get("groupInfo").is_some(),
        });
    }

    if let Some(sent) = envelope
        .get("syncMessage")
        .and_then(|sync| sync.get("sentMessage"))
    {
        let body = string_field(sent, "message")?;
        return Some(Incoming {
            sender_number,
            sender_uuid,
            body,
            is_sync: true,
            is_group: sent.get("groupInfo").is_some(),
        });
    }

    None
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn numbers_match(a: &str, b: &str) -> bool {
    normalize_number(a) == normalize_number(b)
}

fn normalize_number(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect()
}

pub fn find_signal_cli() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("HUSH_SIGNAL_CLI") {
        let path = PathBuf::from(explicit);
        if path.exists() {
            return Some(path);
        }
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("signal-cli");
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = dir.join("signal-cli.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

pub fn require_signal_cli() -> Result<PathBuf, Error> {
    find_signal_cli().ok_or(Error::SignalCliMissing)
}

pub struct Rpc {
    reader: BufReader<Box<dyn Read + Send>>,
    writer: Box<dyn Write + Send>,
    child: Option<Child>,
    next_id: u64,
}

impl Rpc {
    pub fn spawn_jsonrpc(signal_cli: &Path, account: &str) -> Result<Self, Error> {
        let mut child = Command::new(signal_cli)
            .args([
                "-a",
                account,
                "jsonRpc",
                "--ignore-attachments",
                "--ignore-stories",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::user("signal-cli stdout missing"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::user("signal-cli stdin missing"))?;
        Ok(Self {
            reader: BufReader::new(Box::new(stdout)),
            writer: Box::new(stdin),
            child: Some(child),
            next_id: 1,
        })
    }

    #[cfg(unix)]
    pub fn connect_socket(path: &Path) -> Result<Self, Error> {
        let stream = std::os::unix::net::UnixStream::connect(path)?;
        let reader_stream = stream.try_clone()?;
        Ok(Self {
            reader: BufReader::new(Box::new(reader_stream)),
            writer: Box::new(stream),
            child: None,
            next_id: 1,
        })
    }

    pub fn read_line(&mut self) -> Result<Option<String>, Error> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(line))
    }

    pub fn send_text(&mut self, recipient: &str, message: &str) -> Result<(), Error> {
        let id = self.next_id;
        self.next_id += 1;
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "send",
            "id": format!("hush-ack-{id}"),
            "params": {
                "recipient": [recipient],
                "message": message,
            }
        });
        writeln!(self.writer, "{payload}")?;
        self.writer.flush()?;
        Ok(())
    }
}

impl Drop for Rpc {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub fn link_device(signal_cli: &Path, device_name: &str) -> Result<Option<String>, Error> {
    let mut child = Command::new(signal_cli)
        .args(["link", "-n", device_name])
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::user("signal-cli stdout missing"))?;
    let mut reader = BufReader::new(stdout);
    let mut first = String::new();
    reader.read_line(&mut first)?;
    let url = first.trim();
    if url.starts_with("sgnl://")
        || url.starts_with("https://signal.group")
        || url.contains("linkdevice")
    {
        if let Err(err) = qr2term::print_qr(url) {
            eprintln!("hush: could not render QR ({err})");
        }
        println!("{url}");
    } else if !first.is_empty() {
        print!("{first}");
    }
    std::io::copy(&mut reader, &mut std::io::stdout())?;
    let status = child.wait()?;
    if !status.success() {
        return Err(Error::user(format!("signal-cli link failed with {status}")));
    }
    Ok(list_accounts(signal_cli)?.into_iter().next())
}

pub fn list_accounts(signal_cli: &Path) -> Result<Vec<String>, Error> {
    let output = Command::new(signal_cli)
        .args(["--output=json", "listAccounts"])
        .output()?;
    if output.status.success() {
        if let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) {
            return Ok(accounts_from_json(&value));
        }
    }
    let output = Command::new(signal_cli).arg("listAccounts").output()?;
    if !output.status.success() {
        return Err(Error::user(
            "signal-cli listAccounts failed; is a device linked?",
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('+'))
        .map(ToOwned::to_owned)
        .collect())
}

fn accounts_from_json(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                item.as_str()
                    .map(ToOwned::to_owned)
                    .or_else(|| string_field(item, "number"))
                    .or_else(|| string_field(item, "account"))
            })
            .collect(),
        Value::Object(_) => string_field(value, "number")
            .or_else(|| string_field(value, "account"))
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

pub fn receive_once(account: &str, timeout_secs: u64) -> Result<String, Error> {
    let signal_cli = require_signal_cli()?;
    let output = Command::new(&signal_cli)
        .args([
            "-a",
            account,
            "--output=json",
            "--ignore-attachments",
            "--ignore-stories",
            "receive",
            "-t",
            &timeout_secs.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            return Err(Error::user("signal-cli receive failed"));
        }
        return Err(Error::user(format!("signal-cli receive failed: {stderr}")));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn send_ack(account: &str, recipient: &str, name: &str) -> Result<(), Error> {
    let signal_cli = require_signal_cli()?;
    let message = format!("hush: stored {name}");
    let status = Command::new(signal_cli)
        .args(["-a", account, "send", "-m", &message, recipient])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::user("signal-cli send ack failed"))
    }
}

pub fn open_rpc(config: &Config) -> Result<Rpc, Error> {
    let signal_cli = require_signal_cli()?;
    let account = config.signal.account.as_deref().ok_or(Error::NotLinked)?;
    #[cfg(unix)]
    if let Some(socket) = config.signal.socket.as_deref() {
        return Rpc::connect_socket(Path::new(socket));
    }
    Rpc::spawn_jsonrpc(&signal_cli, account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_data_message() {
        let rpc = json!({
            "jsonrpc": "2.0",
            "method": "receive",
            "params": {
                "envelope": {
                    "source": "+33123456789",
                    "sourceNumber": "+33123456789",
                    "sourceUuid": "abc",
                    "dataMessage": {
                        "message": "hush put stripe-prod\nsk-live"
                    }
                }
            }
        });
        let incoming = incoming_from_rpc(&rpc).unwrap();
        assert_eq!(incoming.body, "hush put stripe-prod\nsk-live");
        assert!(!incoming.is_sync);
        assert!(incoming.allowed(&["+33123456789".into()], None));
        assert!(!incoming.allowed(&["self".into()], Some("+1000")));
    }

    #[test]
    fn parses_note_to_self() {
        let rpc = json!({
            "jsonrpc": "2.0",
            "method": "receive",
            "params": {
                "envelope": {
                    "sourceNumber": "+15551234567",
                    "syncMessage": {
                        "sentMessage": {
                            "destination": "+15551234567",
                            "message": "hush put github-pat\ntok"
                        }
                    }
                }
            }
        });
        let incoming = incoming_from_rpc(&rpc).unwrap();
        assert!(incoming.is_sync);
        assert!(incoming.allowed(&["self".into()], Some("+15551234567")));
        assert_eq!(incoming.sender_label(Some("+15551234567")), "self");
    }

    #[test]
    fn ignores_groups_and_non_receive() {
        let group = json!({
            "jsonrpc": "2.0",
            "method": "receive",
            "params": {
                "envelope": {
                    "dataMessage": {
                        "message": "hush put x\nsecret",
                        "groupInfo": {"groupId": "abc"}
                    }
                }
            }
        });
        let incoming = incoming_from_rpc(&group).unwrap();
        assert!(incoming.is_group);

        let other = json!({"jsonrpc":"2.0","id":"1","result":{}});
        assert!(incoming_from_rpc(&other).is_none());
    }

    #[test]
    fn parses_receive_cli_json() {
        let stdout = r#"{"envelope":{"sourceNumber":"+15551234567","syncMessage":{"sentMessage":{"message":"plain-secret"}}}}"#;
        let list = incoming_list_from_stdout(stdout);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].body, "plain-secret");
        assert!(list[0].is_sync);
    }
}
