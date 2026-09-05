use hush::{vault::Vault, Paths};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};
use tempfile::TempDir;

fn exercise(mode: &str, extra: &[&str]) -> (TempDir, std::process::Output) {
    let tmp = TempDir::new().unwrap();
    let paths = Paths::new(tmp.path().join("vault"));
    assert!(Command::new(env!("CARGO_BIN_EXE_hush"))
        .args(["--home", paths.root().to_str().unwrap(), "init"])
        .output()
        .unwrap()
        .status
        .success());
    let vault = Vault::open(&paths).unwrap();
    vault
        .put("example", b"synthetic-send-secret", "test", "self")
        .unwrap();
    vault
        .put("BITWARDEN_SESSION", b"synthetic-session", "test", "self")
        .unwrap();
    let fake = tmp.path().join("bw");
    fs::write(&fake, r##"#!/usr/bin/env python3
import base64, json, os, sys
payload=sys.stdin.buffer.read()
assert os.environ['BW_SESSION'] in ('synthetic-session','ambient-session')
assert 'BW_PASSWORD' not in os.environ
assert 'BW_CLIENTSECRET' not in os.environ
if sys.argv[1:]==['encode']:
 print(base64.b64encode(payload).decode())
elif sys.argv[1:]==['send','create']:
 value=json.loads(base64.b64decode(payload))
 assert value['text']=={'text':'synthetic-send-secret','hidden':True}
 assert value['type']==0 and value['hideEmail'] and not value['disabled']
 assert value['expirationDate']==value['deletionDate']
 if os.environ['MODE']=='failure':
  print('synthetic-send-secret',file=sys.stderr)
  print('synthetic-session')
  sys.exit(1)
 if os.environ['MODE']=='badreceipt': print('https://example.test/#synthetic-send-secret')
 else:
  with open(os.environ['RECEIPT'], 'w') as f: json.dump({'expiry':value['expirationDate'],'limit':value['maxAccessCount'],'title':value['name']},f)
  if os.environ['MODE']=='json': print(json.dumps({'object':'send','accessUrl':'https://send.bitwarden.com/#opaque-id/opaque-key','text':value['text'],'key':'internal-encryption-key'}))
  else: print('https://send.bitwarden.com/#opaque-id/opaque-key')
else: sys.exit(2)
"##).unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_hush"));
    command
        .args([
            "--home",
            paths.root().to_str().unwrap(),
            "send",
            "--name",
            "example",
            "--json",
        ])
        .args(extra)
        .env_remove("BW_SESSION")
        .env("BW_PASSWORD", "unrelated-password")
        .env("BW_CLIENTSECRET", "unrelated-client-secret")
        .env("HUSH_BW_BIN", fake)
        .env("MODE", mode)
        .env("RECEIPT", tmp.path().join("receipt.json"));
    if mode == "ambient" {
        command.env("BW_SESSION", "ambient-session");
    }
    let output = command.output().unwrap();
    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in [
        "synthetic-send-secret",
        "synthetic-session",
        "ambient-session",
        "unrelated-password",
        "unrelated-client-secret",
    ] {
        assert!(!output_text.contains(secret));
    }
    (tmp, output)
}

#[test]
fn creates_hidden_expiring_send_from_stored_session() {
    let (tmp, out) = exercise(
        "success",
        &[
            "--title",
            "Example access",
            "--days",
            "3",
            "--max-access-count",
            "8",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(tmp.path().join("receipt.json")).unwrap()).unwrap();
    assert_eq!(value["event"], "send-created");
    assert_eq!(value["max_access_count"], 8);
    assert_eq!(receipt["limit"], 8);
    assert_eq!(receipt["title"], "Example access");
    let expiry =
        chrono::DateTime::parse_from_rfc3339(value["expires_at"].as_str().unwrap()).unwrap();
    assert!((expiry.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds() > 258000);
}

#[test]
fn supports_ambient_session_and_safe_failures() {
    let (_, json) = exercise("json", &[]);
    assert!(json.status.success());
    assert!(!String::from_utf8_lossy(&json.stdout).contains("internal-encryption-key"));
    assert!(exercise("ambient", &[]).1.status.success());
    assert!(!exercise("failure", &[]).1.status.success());
    assert!(!exercise("badreceipt", &[]).1.status.success());
}

#[test]
fn rejects_invalid_lifespans_and_access_limits() {
    for args in [
        ["--days", "0"],
        ["--days", "32"],
        ["--max-access-count", "0"],
    ] {
        let (tmp, out) = exercise("success", &args);
        assert!(!out.status.success());
        assert!(!tmp.path().join("receipt.json").exists());
    }
}
