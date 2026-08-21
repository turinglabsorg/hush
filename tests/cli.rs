use std::process::Command;

use hush::paths::Paths;
use hush::vault::Vault;
use tempfile::TempDir;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hush"))
}

fn home_args(home: &std::path::Path) -> Vec<String> {
    vec!["--home".into(), home.display().to_string()]
}

#[test]
fn init_list_run_does_not_print_secret() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("hush");

    let init = bin().args(home_args(&home)).arg("init").output().unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );

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
    let output = bin()
        .args(home_args(&home))
        .args(["init"])
        .output()
        .unwrap();
    assert!(output.status.success());

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
fn help_lists_pull() {
    let output = bin().arg("pull").arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--name"));
    assert!(help.contains("--json"));
}
