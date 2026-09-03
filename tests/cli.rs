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

    fn send_gated(&self, id: &str, name: &str, text: &str, email: &str, code: &str) {
        self.send(id, name, text, None);
        fs::write(self.dir.join("sends").join(format!("{id}.email")), email).unwrap();
        fs::write(self.dir.join("sends").join(format!("{id}.code")), code).unwrap();
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
fn pull_send_gated_with_code_hook() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    let bw = FakeBw::new();
    bw.send_gated(
        "gated1",
        "gated-secret",
        "gated-SEND-SECRET",
        "agent@example.com",
        "827126",
    );
    // The hook contract: print ONLY the code. Like a real mailbox, the
    // code only exists after bw mints it (the fixture drops a marker),
    // so early polls must come back empty and hush must wait, not submit
    // stale output.
    let hook = format!(
        "if [ -f {} ]; then cat {}; fi",
        bw.dir.join("sends").join("gated1.minted").display(),
        bw.dir.join("sends").join("gated1.code").display()
    );

    let mut cmd = bin();
    bw.apply(&mut cmd);
    let out = cmd
        .args(home_args(&home))
        .args([
            "pull",
            "--name",
            "gated-secret",
            "--send",
            "https://vault.bitwarden.com/#/send/gated1",
            "--email",
            "agent@example.com",
            "--code-cmd",
            &hook,
            "--code-timeout",
            "30",
            "--code-poll",
            "1",
            "--json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("gated-secret"));
    assert!(!stdout.contains("gated-SEND-SECRET"));
    assert!(!stdout.contains("827126"));
    assert!(!stderr.contains("gated-SEND-SECRET"));
    assert!(!stderr.contains("827126"));

    let paths = Paths::new(home);
    assert_eq!(
        &Vault::open(&paths).unwrap().get("gated-secret").unwrap()[..],
        b"gated-SEND-SECRET"
    );
}

#[test]
fn pull_send_gated_wrong_code_fails_without_storing() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    let bw = FakeBw::new();
    bw.send_gated(
        "gated2",
        "gated-secret",
        "gated-SEND-SECRET",
        "agent@example.com",
        "827126",
    );

    let mut cmd = bin();
    bw.apply(&mut cmd);
    let out = cmd
        .args(home_args(&home))
        .args([
            "pull",
            "--name",
            "gated-secret",
            "--send",
            "https://vault.bitwarden.com/#/send/gated2",
            "--email",
            "agent@example.com",
            "--codeenv",
            "HUSH_TEST_WRONG_CODE",
            "--json",
        ])
        .env("HUSH_TEST_WRONG_CODE", "000000")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("rejected"), "stderr={stderr}");
    assert!(stderr.contains("fresh code"), "stderr={stderr}");
    assert!(!stderr.contains("gated-SEND-SECRET"));

    let paths = Paths::new(home);
    assert!(Vault::open(&paths).unwrap().get("gated-secret").is_err());
}

#[test]
fn pull_send_gated_without_email_hints_at_flag() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    let bw = FakeBw::new();
    bw.send_gated(
        "gated3",
        "gated-secret",
        "gated-SEND-SECRET",
        "agent@example.com",
        "827126",
    );

    // Plain receive against a gated Send fails opaquely; hush must point
    // at --email instead of surfacing a confusing error.
    let mut cmd = bin();
    bw.apply(&mut cmd);
    let out = cmd
        .args(home_args(&home))
        .args([
            "pull",
            "--name",
            "gated-secret",
            "--send",
            "https://vault.bitwarden.com/#/send/gated3",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--email ADDRESS"), "stderr={stderr}");
    assert!(!stderr.contains("gated-SEND-SECRET"));
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

#[test]
fn run_scrubs_secret_bearing_env() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    let paths = Paths::new(home.clone());
    Vault::open(&paths)
        .unwrap()
        .put("token", b"s3cret-value-xyz", "test", "self")
        .unwrap();

    // Even if the agent process holds a Bitwarden session, the child must
    // not inherit it: it could otherwise call `bw` directly, bypassing hush.
    let out = bin()
        .env("BW_SESSION", "leak-me")
        .env("BW_CLIENTSECRET", "leak-me")
        .env("BITWARDENCLI_APPDATA_DIR", "/tmp/hush-leak-probe")
        .args(home_args(&home))
        .args(["run", "--name", "token", "--env", "SECRET", "--"])
        .args([
            "sh",
            "-c",
            r#"test -z "${BW_SESSION:-}" && test -z "${BW_CLIENTSECRET:-}" && test -z "${BITWARDENCLI_APPDATA_DIR:-}" && test "$SECRET" = s3cret-value-xyz"#,
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr={stderr}");
}

#[test]
fn run_redact_filters_secret_from_output() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    let paths = Paths::new(home.clone());
    Vault::open(&paths)
        .unwrap()
        .put("token", b"s3cret-value-xyz", "test", "self")
        .unwrap();

    // The child deliberately echoes the secret: --redact must catch it on
    // both stdout and stderr so it never reaches the transcript.
    let out = bin()
        .args(home_args(&home))
        .args([
            "run", "--name", "token", "--env", "SECRET", "--redact", "--",
        ])
        .args(["sh", "-c", "echo leak=$SECRET; echo err=$SECRET >&2"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("[redacted by hush]"), "stdout={stdout}");
    assert!(stderr.contains("[redacted by hush]"), "stderr={stderr}");
    assert!(!stdout.contains("s3cret-value-xyz"), "stdout={stdout}");
    assert!(!stderr.contains("s3cret-value-xyz"), "stderr={stderr}");

    // Exit codes still propagate in redact mode.
    let out = bin()
        .args(home_args(&home))
        .args([
            "run", "--name", "token", "--env", "SECRET", "--redact", "--",
        ])
        .args(["sh", "-c", "exit 3"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn agent_shim_blocks_direct_bw() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("shim");
    let out = bin()
        .args(["agent-shim", "--dir"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(out.status.success());
    let shim = dir.join("bw");
    assert!(shim.is_file());

    for args in [
        vec!["get", "password", "x"],
        vec!["send", "receive", "https://example.com/#/send/abc"],
        vec!["status"],
    ] {
        let out = Command::new(&shim).args(&args).output().unwrap();
        assert!(!out.status.success(), "args={args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("hush"), "stderr={stderr}");
    }
}

#[test]
fn agent_shim_refuses_to_clobber_real_binary() {
    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join("bw"), "real binary").unwrap();
    let out = bin()
        .args(["agent-shim", "--dir"])
        .arg(tmp.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        fs::read_to_string(tmp.path().join("bw")).unwrap(),
        "real binary"
    );
    let out = bin()
        .args(["agent-shim", "--dir"])
        .arg(tmp.path())
        .arg("--force")
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[cfg(unix)]
#[test]
fn doctor_fails_on_loose_identity_perms() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");
    init_home(&home);
    fs::set_permissions(home.join("identity"), fs::Permissions::from_mode(0o644)).unwrap();

    let bw = FakeBw::new();
    let mut cmd = bin();
    bw.apply(&mut cmd);
    let out = cmd
        .args(home_args(&home))
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["ok"], false);
    let issues = report["issues"].to_string();
    assert!(issues.contains("identity"), "issues={issues}");
}
