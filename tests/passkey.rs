use hush::{vault::Vault, Paths};
use std::process::Command;
use tempfile::TempDir;

const PIN: &str = "synthetic-passkey-verification-pin";
fn setup() -> (TempDir, Paths) {
    let tmp = TempDir::new().unwrap();
    let paths = Paths::new(tmp.path().join("vault"));
    let vault = Vault::init(&paths).unwrap();
    vault
        .put("test-pin", PIN.as_bytes(), "test", "self")
        .unwrap();
    (tmp, paths)
}
fn bin(paths: &Paths) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hush"));
    cmd.args(["--home", paths.root().to_str().unwrap()])
        .env("HUSH_PASSKEY_PIN", PIN);
    cmd
}
fn create(paths: &Paths, name: &str) -> std::process::Output {
    bin(paths)
        .args([
            "passkey",
            "create",
            name,
            "--rp-id",
            "localhost",
            "--origin",
            "http://localhost:3010",
            "--pin-secret",
            "test-pin",
            "--json",
        ])
        .output()
        .unwrap()
}
#[test]
fn creates_encrypted_passkey_and_only_reports_public_metadata() {
    let (_tmp, paths) = setup();
    let out = create(&paths, "test-passkey");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(metadata["prf"] == true && metadata["algorithm"] == "RS256");
    for output in [&out.stdout, &out.stderr] {
        let text = String::from_utf8_lossy(output);
        assert!(!text.contains(PIN) && !text.contains("private_key") && !text.contains("prf_key"));
    }
    let ciphertext = std::fs::read(paths.secret_file("test-passkey")).unwrap();
    assert!(ciphertext.starts_with(b"age-encryption.org/"));
    assert!(!create(&paths, "test-passkey").status.success());
    assert!(bin(&paths)
        .args(["passkey", "info", "test-passkey", "--json"])
        .status()
        .unwrap()
        .success());
}
#[test]
fn rejects_invalid_origins_and_wrong_verification_without_leaks() {
    let (_tmp, paths) = setup();
    for origin in [
        "http://evil.test",
        "https://evil.test",
        "https://localhost/extra",
        "https://user@localhost",
        "https://localhost?x=1",
    ] {
        assert!(!bin(&paths)
            .args([
                "passkey",
                "create",
                "denied",
                "--rp-id",
                "localhost",
                "--origin",
                origin,
                "--pin-secret",
                "test-pin"
            ])
            .output()
            .unwrap()
            .status
            .success());
    }
    let out = bin(&paths)
        .env("HUSH_PASSKEY_PIN", "wrong-private-pin")
        .args([
            "passkey",
            "create",
            "denied",
            "--rp-id",
            "localhost",
            "--origin",
            "https://localhost",
            "--pin-secret",
            "test-pin",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("wrong-private-pin"));
    assert!(Vault::open(&paths).unwrap().info("denied").is_err());
}
#[test]
fn private_key_cannot_escape_through_generic_run_or_send() {
    let (_tmp, paths) = setup();
    assert!(create(&paths, "key").status.success());
    for args in [
        vec![
            "run", "--name", "key", "--env", "SECRET", "--redact", "--", "sh", "-c", "exit 95",
        ],
        vec!["send", "--name", "key", "--json"],
    ] {
        let out = bin(&paths).args(args).output().unwrap();
        assert!(!out.status.success() && out.status.code() != Some(95));
        assert!(!String::from_utf8_lossy(&out.stderr).contains("private_key"));
    }
}
#[test]
fn worker_output_is_private_and_invalid_protocol_is_suppressed() {
    let (_tmp, paths) = setup();
    assert!(create(&paths, "key").status.success());
    let out = bin(&paths)
        .args([
            "passkey",
            "run",
            "--name",
            "key",
            "--",
            "sh",
            "-c",
            "printf 'PRIVATE-LEAK\\n'; printf 'PRIVATE-LEAK' >&2",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("PRIVATE-LEAK"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("PRIVATE-LEAK"));
    let out = bin(&paths)
        .env("HUSH_PASSKEY_PIN", "wrong")
        .args([
            "passkey", "run", "--name", "key", "--", "sh", "-c", "exit 95",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success() && out.status.code() != Some(95));
}
#[test]
fn nested_hush_run_verifies_pin_without_exposing_it_to_worker() {
    let (_tmp, paths) = setup();
    assert!(create(&paths, "key").status.success());
    let out = bin(&paths)
        .env("BW_SESSION", "ambient-private-session")
        .args([
            "run",
            "--name",
            "test-pin",
            "--env",
            "HUSH_PASSKEY_PIN",
            "--redact",
            "--",
            env!("CARGO_BIN_EXE_hush"),
            "--home",
            paths.root().to_str().unwrap(),
            "passkey",
            "run",
            "--name",
            "key",
            "--",
            "sh",
            "-c",
            "test -z \"${HUSH_PASSKEY_PIN+x}\" && test -z \"${BW_SESSION+x}\"",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains(PIN));
}
#[test]
fn requests_round_trip_through_private_pipes() {
    let (_tmp, paths) = setup();
    assert!(create(&paths, "key").status.success());
    let script = r#"import sys,json
req={'op':'create','origin':'http://localhost:3010','publicKey':{'challenge':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','rp':{'id':'localhost'},'user':{'id':'AQID'},'pubKeyCredParams':[{'type':'public-key','alg':-257}],'extensions':{'prf':{}}}}
print(json.dumps(req),flush=True)
res=json.loads(sys.stdin.readline()); assert res['ok'] and res['credential']['clientExtensionResults']['prf']['enabled']
req={'op':'get','origin':'http://localhost:3010','publicKey':{'challenge':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','rpId':'localhost','extensions':{'prf':{'eval':{'first':'AQID','second':'BAUG'}}}}}
print(json.dumps(req),flush=True)
res=json.loads(sys.stdin.readline()); assert res['ok']; a=res['credential']['clientExtensionResults']['prf']['results']; assert len(a['first'])==43 and a['first']!=a['second']
req['origin']='https://foreign.test';print(json.dumps(req),flush=True); assert not json.loads(sys.stdin.readline())['ok']
"#;
    let out = bin(&paths)
        .args([
            "passkey", "run", "--name", "key", "--", "python3", "-c", script,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("session-completed"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("results"));
}
#[test]
fn refuses_parallel_credential_use_and_removes_own_lock() {
    let (_tmp, paths) = setup();
    assert!(create(&paths, "key").status.success());
    std::fs::write(paths.vault_dir().join("key.passkey-lock"), b"").unwrap();
    let out = bin(&paths)
        .args(["passkey", "run", "--name", "key", "--", "true"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    std::fs::remove_file(paths.vault_dir().join("key.passkey-lock")).unwrap();
    let out = bin(&paths)
        .args(["passkey", "run", "--name", "key", "--", "true"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!paths.vault_dir().join("key.passkey-lock").exists());
}

#[test]
fn management_cannot_replace_or_delete_an_active_passkey() {
    let (_tmp, paths) = setup();
    assert!(create(&paths, "key").status.success());
    let out = bin(&paths)
        .args(["generate", "key", "--force", "--json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let out = bin(&paths)
        .args(["passkey", "list", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let receipt: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(receipt["passkeys"].as_array().unwrap().len() == 1);
    std::fs::write(paths.vault_dir().join("key.passkey-lock"), b"").unwrap();
    assert!(!bin(&paths)
        .args(["rm", "key"])
        .output()
        .unwrap()
        .status
        .success());
    std::fs::remove_file(paths.vault_dir().join("key.passkey-lock")).unwrap();
    assert!(bin(&paths)
        .args(["passkey", "rm", "key"])
        .output()
        .unwrap()
        .status
        .success());
    assert!(!bin(&paths)
        .args(["passkey", "info", "key"])
        .output()
        .unwrap()
        .status
        .success());
    assert!(Vault::open(&paths).unwrap().info("test-pin").is_ok());
}
