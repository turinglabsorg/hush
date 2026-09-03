use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use hush::paths::Paths;
use hush::vault::Vault;
use tempfile::TempDir;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hush"))
}

fn home_args(home: &Path) -> Vec<String> {
    vec!["--home".into(), home.display().to_string()]
}

fn fixture_bw() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("fake-bw.sh")
}

/// A fake Bitwarden backend: HUSH_BW_BIN points at the fixture,
/// FAKE_BW_DIR holds items/<id>.json and sends/<id>.txt.
struct FakeBw {
    _tmp: TempDir,
    dir: PathBuf,
}

impl FakeBw {
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("bw");
        fs::create_dir_all(dir.join("items")).unwrap();
        fs::create_dir_all(dir.join("sends")).unwrap();
        Self { _tmp: tmp, dir }
    }

    fn state(&self, state: &str) {
        fs::write(self.dir.join("state"), state).unwrap();
    }

    fn item(&self, id: &str, name: &str, password: Option<&str>, notes: Option<&str>) {
        let payload = serde_json::json!({
            "id": id,
            "name": name,
            "login": password.map(|pw| serde_json::json!({"password": pw})),
            "notes": notes,
        });
        fs::write(
            self.dir.join("items").join(format!("{id}.json")),
            serde_json::to_string(&payload).unwrap(),
        )
        .unwrap();
    }

    fn send(&self, id: &str, name: &str, text: &str, password: Option<&str>) {
        fs::write(self.dir.join("sends").join(format!("{id}.name")), name).unwrap();
        fs::write(self.dir.join("sends").join(format!("{id}.txt")), text).unwrap();
        if let Some(pw) = password {
            fs::write(self.dir.join("sends").join(format!("{id}.password")), pw).unwrap();
        }
    }

    fn apply(&self, cmd: &mut Command) {
        cmd.env("HUSH_BW_BIN", fixture_bw());
        cmd.env("FAKE_BW_DIR", &self.dir);
    }

    fn has_item(&self, id: &str) -> bool {
        self.dir.join("items").join(format!("{id}.json")).exists()
    }
}

fn init_home(home: &Path) {
    let out = bin().args(home_args(home)).arg("init").output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn init_list_run_does_not_print_secret() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);

    let paths = Paths::new(home.clone());
    Vault::open(&paths)
        .unwrap()
        .put("token", b"s3cret-value-xyz", "test", "self")
        .unwrap();

    let list = bin()
        .args(home_args(&home))
        .args(["list", "--json"])
        .output()
        .unwrap();
    let list_out = String::from_utf8_lossy(&list.stdout);
    assert!(list.status.success());
    assert!(list_out.contains("token"));
    assert!(!list_out.contains("s3cret-value-xyz"));

    let run = bin()
        .args(home_args(&home))
        .args(["run", "--name", "token", "--env", "SECRET", "--"])
        .args(["sh", "-c", r#"test "$SECRET" = s3cret-value-xyz"#])
        .output()
        .unwrap();
    let run_out = String::from_utf8_lossy(&run.stdout);
    let run_err = String::from_utf8_lossy(&run.stderr);
    assert!(run.status.success(), "stdout={run_out} stderr={run_err}");
    assert!(!run_out.contains("s3cret-value-xyz"));
    assert!(!run_err.contains("s3cret-value-xyz"));
}

#[test]
fn no_show_command() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);

    let show = bin().args(home_args(&home)).arg("show").output().unwrap();
    assert!(!show.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&show.stdout),
        String::from_utf8_lossy(&show.stderr)
    );
    assert!(!combined.to_ascii_lowercase().contains("s3cret"));
}

#[test]
fn help_lists_pull_flags() {
    let output = bin().arg("pull").arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--name"));
    assert!(help.contains("--send"));
    assert!(help.contains("--json"));
}

#[test]
fn pull_send_stores_without_printing_secret() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    let bw = FakeBw::new();
    bw.send("abc123", "stripe-prod", "sk-live-SEND-SECRET", None);

    let mut cmd = bin();
    bw.apply(&mut cmd);
    let out = cmd
        .args(home_args(&home))
        .args([
            "pull",
            "--name",
            "stripe-prod",
            "--send",
            "https://vault.bitwarden.com/#/send/abc123",
            "--json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("stripe-prod"));
    assert!(!stdout.contains("sk-live-SEND-SECRET"));
    assert!(!stderr.contains("sk-live-SEND-SECRET"));

    let paths = Paths::new(home);
    assert_eq!(
        &Vault::open(&paths).unwrap().get("stripe-prod").unwrap()[..],
        b"sk-live-SEND-SECRET"
    );
}

#[test]
fn pull_send_requires_name() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    let bw = FakeBw::new();

    let mut cmd = bin();
    bw.apply(&mut cmd);
    let out = cmd
        .args(home_args(&home))
        .args([
            "pull",
            "--send",
            "https://vault.bitwarden.com/#/send/abc123",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn pull_send_with_passwordenv() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    let bw = FakeBw::new();
    bw.send("pw1", "locked-secret", "top-secret-value", Some("send-pw"));

    let mut cmd = bin();
    bw.apply(&mut cmd);
    cmd.env("HUSH_TEST_SEND_PW", "send-pw");
    let out = cmd
        .args(home_args(&home))
        .args([
            "pull",
            "--name",
            "locked-secret",
            "--send",
            "https://vault.bitwarden.com/#/send/pw1",
            "--passwordenv",
            "HUSH_TEST_SEND_PW",
            "--json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout={stdout} stderr={stderr}");
    assert!(!stdout.contains("top-secret-value"));

    let mut cmd = bin();
    bw.apply(&mut cmd);
    let out = cmd
        .args(home_args(&home))
        .args([
            "pull",
            "--name",
            "other",
            "--send",
            "https://vault.bitwarden.com/#/send/pw1",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "passwordless receive must fail");
}

#[test]
fn pull_named_vault_item() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    let bw = FakeBw::new();
    bw.item("item-1", "github-pat", Some("ghp_ITEM-SECRET"), None);

    let mut cmd = bin();
    bw.apply(&mut cmd);
    let out = cmd
        .args(home_args(&home))
        .args(["pull", "--name", "github-pat", "--json"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout={stdout} stderr={stderr}");
    assert!(!stdout.contains("ghp_ITEM-SECRET"));

    let paths = Paths::new(home);
    assert_eq!(
        &Vault::open(&paths).unwrap().get("github-pat").unwrap()[..],
        b"ghp_ITEM-SECRET"
    );
    assert!(bw.has_item("item-1"), "no --consume: item stays");
}

#[test]
fn pull_scan_ingests_command_items_and_consume_trashes() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    let bw = FakeBw::new();
    bw.item("item-9", "hush put db-pass", None, Some("db-SCAN-SECRET"));
    bw.item("item-10", "random login", Some("nothing-shared"), None);

    let mut cmd = bin();
    bw.apply(&mut cmd);
    let out = cmd
        .args(home_args(&home))
        .args(["pull", "--json", "--consume"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("db-pass"));
    assert!(!stdout.contains("db-SCAN-SECRET"));

    let paths = Paths::new(home);
    assert_eq!(
        &Vault::open(&paths).unwrap().get("db-pass").unwrap()[..],
        b"db-SCAN-SECRET"
    );
    assert!(!bw.has_item("item-9"), "consumed item is trashed");
    assert!(bw.has_item("item-10"), "unrelated item stays");
}

#[test]
fn pull_fails_when_vault_locked() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    let bw = FakeBw::new();
    bw.state("locked");
    bw.item("item-1", "github-pat", Some("x"), None);

    let mut cmd = bin();
    bw.apply(&mut cmd);
    let out = cmd
        .args(home_args(&home))
        .args(["pull", "--name", "github-pat", "--json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("locked or not logged in"));
}

#[test]
fn doctor_reports_unlocked_vault() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    let bw = FakeBw::new();

    let mut cmd = bin();
    bw.apply(&mut cmd);
    let out = cmd
        .args(home_args(&home))
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout={stdout}");
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["bitwarden_state"], "unlocked");
}

#[test]
fn bitwarden_status_reports_state() {
    let bw = FakeBw::new();

    let mut cmd = bin();
    bw.apply(&mut cmd);
    let out = cmd
        .args(["bitwarden", "status", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let payload: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(payload["state"], "unlocked");
    assert_eq!(payload["user_email"], "agent@example.com");
}
