use std::io::Write;
use std::process::{Command, Stdio};

use hush::{vault::Vault, Paths};
use tempfile::TempDir;

const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn vault() -> (TempDir, Paths) {
    let directory = TempDir::new().unwrap();
    let paths = Paths::new(directory.path().join("hush"));
    Vault::init(&paths).unwrap();
    (directory, paths)
}

fn bin(paths: &Paths) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hush"));
    command.args(["--home", paths.root().to_str().unwrap()]);
    command
}

#[test]
fn stores_enrollment_from_stdin_without_printing_seed() {
    let (_directory, paths) = vault();
    let mut child = bin(&paths)
        .args(["totp", "store", "--name", "google-otp", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(SEED.as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains(SEED));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(SEED));
    assert!(String::from_utf8_lossy(&result.stdout).contains("google-otp"));
    assert_eq!(
        &Vault::open(&paths).unwrap().get("google-otp").unwrap()[..],
        SEED.as_bytes()
    );
}

#[test]
fn totp_injection_redacts_code_and_seed_and_scrubs_bitwarden() {
    let (_directory, paths) = vault();
    Vault::open(&paths)
        .unwrap()
        .put("google-otp", SEED.as_bytes(), "test", "self")
        .unwrap();
    let result = bin(&paths)
        .args([
            "run",
            "--name",
            "google-otp",
            "--env",
            "LOGIN_OTP",
            "--totp",
            "--redact",
            "--",
            "sh",
            "-c",
        ])
        .arg(format!(
            r#"
            test "${{#LOGIN_OTP}}" -eq 6 || exit 7
            case "$LOGIN_OTP" in *[!0-9]*) exit 8;; esac
            test -z "${{BW_SESSION+x}}" || exit 9
            test -z "${{BITWARDENCLI_APPDATA_DIR+x}}" || exit 10
            printf '%s:%s' "$LOGIN_OTP" '{SEED}'
            printf '%s:%s' '{SEED}' "$LOGIN_OTP" >&2
        "#
        ))
        .env("BW_SESSION", "test-session-must-not-be-inherited")
        .env(
            "BITWARDENCLI_APPDATA_DIR",
            "/test-profile-must-not-be-inherited",
        )
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"[redacted by hush]:[redacted by hush]");
    assert_eq!(result.stderr, b"[redacted by hush]:[redacted by hush]");
}

#[test]
fn totp_requires_output_redaction_and_rejects_bad_seed_without_leaking() {
    let (_directory, paths) = vault();
    let invalid = "private-invalid-seed!";
    Vault::open(&paths)
        .unwrap()
        .put("google-otp", invalid.as_bytes(), "test", "self")
        .unwrap();
    for flags in [vec!["--totp"], vec!["--totp", "--redact"]] {
        let result = bin(&paths)
            .args(["run", "--name", "google-otp", "--env", "LOGIN_OTP"])
            .args(flags)
            .args(["--", "sh", "-c", "exit 93"])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert_ne!(result.status.code(), Some(93));
        assert!(!String::from_utf8_lossy(&result.stdout).contains(invalid));
        assert!(!String::from_utf8_lossy(&result.stderr).contains(invalid));
    }
}

#[test]
fn enrollment_refuses_to_replace_existing_identity() {
    let (_directory, paths) = vault();
    Vault::open(&paths)
        .unwrap()
        .put("google-otp", SEED.as_bytes(), "test", "self")
        .unwrap();
    let mut child = bin(&paths)
        .args(["totp", "store", "--name", "google-otp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(b"JBSWY3DPEHPK3PXP");
    let result = child.wait_with_output().unwrap();
    assert!(!result.status.success());
    assert_eq!(
        &Vault::open(&paths).unwrap().get("google-otp").unwrap()[..],
        SEED.as_bytes()
    );
}
