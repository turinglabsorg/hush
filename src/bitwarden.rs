use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::paths::Paths;
use crate::vault::Vault;
use crate::Error;

pub const DEFAULT_SESSION_SECRET: &str = "BITWARDEN_SESSION";

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
    parse_status(&out)
}

pub fn managed_status(paths: &Paths) -> Result<(BwStatus, bool), Error> {
    let Ok(vault) = Vault::open(paths) else {
        return status().map(|status| (status, false));
    };
    let session = match vault.get(DEFAULT_SESSION_SECRET) {
        Ok(session) => session,
        Err(Error::NotFound(_)) => return status().map(|status| (status, false)),
        Err(err) => return Err(err),
    };
    let session = std::str::from_utf8(&session)
        .map_err(|_| Error::user("stored Bitwarden session is not valid UTF-8"))?;
    status_with_session(session).map(|status| (status, true))
}

fn status_with_session(session: &str) -> Result<BwStatus, Error> {
    let bw = require_bw()?;
    let output = Command::new(bw)
        .arg("status")
        .env_remove("BW_CLIENTID")
        .env_remove("BW_CLIENTSECRET")
        .env_remove("BW_PASSWORD")
        .env("BW_SESSION", session)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        return Err(Error::user(
            "Bitwarden status failed for the stored session; rerun `hush bitwarden unlock`",
        ));
    }
    let out = String::from_utf8(output.stdout)
        .map_err(|_| Error::user("Bitwarden status returned non-text output"))?;
    parse_status(&out)
}

fn parse_status(out: &str) -> Result<BwStatus, Error> {
    let mut parsed: BwStatus =
        serde_json::from_str(out).map_err(|_| Error::user("bw status returned invalid JSON"))?;
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

pub fn login_and_unlock(email: &str, master_password: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    if email.trim().is_empty() || !email.contains('@') {
        return Err(Error::user("a valid Bitwarden email is required"));
    }
    if master_password.is_empty() {
        return Err(Error::user("the stored Bitwarden master password is empty"));
    }

    let bw = require_bw()?;
    let state = status()?.state;
    let output = if state.eq_ignore_ascii_case("unlocked") {
        run_bw_auth(&bw, &["lock"], master_password, "lock")?;
        run_bw_auth(
            &bw,
            &[
                "unlock",
                "--passwordenv",
                "HUSH_BITWARDEN_MASTER_PASSWORD",
                "--raw",
                "--nointeraction",
            ],
            master_password,
            "unlock",
        )?
    } else if state.eq_ignore_ascii_case("locked") {
        run_bw_auth(
            &bw,
            &[
                "unlock",
                "--passwordenv",
                "HUSH_BITWARDEN_MASTER_PASSWORD",
                "--raw",
                "--nointeraction",
            ],
            master_password,
            "unlock",
        )?
    } else {
        run_bw_auth(
            &bw,
            &[
                "login",
                email,
                "--passwordenv",
                "HUSH_BITWARDEN_MASTER_PASSWORD",
                "--raw",
                "--nointeraction",
            ],
            master_password,
            "login",
        )?
    };

    let session = Zeroizing::new(output.trim().as_bytes().to_vec());
    if session.is_empty() {
        return Err(Error::user(
            "Bitwarden authentication returned an empty session",
        ));
    }
    Ok(session)
}

fn run_bw_auth(
    bw: &Path,
    args: &[&str],
    master_password: &str,
    action: &str,
) -> Result<Zeroizing<String>, Error> {
    let output = Command::new(bw)
        .args(args)
        .env_remove("BW_SESSION")
        .env_remove("BW_CLIENTID")
        .env_remove("BW_CLIENTSECRET")
        .env_remove("BW_PASSWORD")
        .env("HUSH_BITWARDEN_MASTER_PASSWORD", master_password)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        return Err(Error::user(format!(
            "Bitwarden {action} failed; verify the account and stored master password"
        )));
    }
    Ok(Zeroizing::new(String::from_utf8(output.stdout).map_err(
        |_| Error::user("Bitwarden returned a non-text session"),
    )?))
}

pub fn sync() -> Result<(), Error> {
    require_unlocked()?;
    run_bw(&["sync"])?;
    Ok(())
}

/// Options for `bw send receive`.
#[derive(Debug, Clone)]
pub struct SendReceiveOptions {
    /// Passthrough flags (`--passwordenv VAR`, `--passwordfile PATH`).
    /// Never a literal password.
    pub password_args: Vec<String>,
    /// If set, drive bw's interactive email-verification flow with this address.
    pub email: Option<String>,
    /// Shell command printing ONLY the verification code (4-8 digits).
    /// Polled until output validates or the timeout elapses. The code is
    /// piped straight into bw and never printed.
    pub code_cmd: Option<String>,
    /// Env var already holding a fresh verification code.
    pub code_env: Option<String>,
    /// File holding a fresh verification code.
    pub code_file: Option<String>,
    /// Overall timeout (secs) for a gated receive, including waiting for
    /// the code email. Default 300.
    pub code_timeout_secs: u64,
    /// Poll interval (secs) for `--code-cmd`. Default 10.
    pub code_poll_secs: u64,
}

impl Default for SendReceiveOptions {
    fn default() -> Self {
        Self {
            password_args: Vec::new(),
            email: None,
            code_cmd: None,
            code_env: None,
            code_file: None,
            code_timeout_secs: 300,
            code_poll_secs: 10,
        }
    }
}

impl SendReceiveOptions {
    pub fn plain(password_args: Vec<String>) -> Self {
        Self {
            password_args,
            ..Self::default()
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.code_timeout_secs.max(5))
    }

    fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.code_poll_secs.clamp(1, 60))
    }
}

/// Receive a Bitwarden Send by URL. Works without an unlocked vault;
/// the URL itself is not secret, the Send content is.
///
/// Without `--email` this is a single non-interactive call. Gated Sends
/// (restricted to an email address) fail opaquely there, so an empty or
/// failed plain receive points at `--email`. With `--email`, hush drives
/// bw's interactive email/code prompts over pipes.
pub fn send_receive(url: &str, opts: &SendReceiveOptions) -> Result<Vec<u8>, Error> {
    match &opts.email {
        None => send_receive_plain(url, &opts.password_args).and_then(|out| {
            if out.iter().all(|b| b.is_ascii_whitespace()) {
                Err(Error::user(
                    "bw returned empty output (hint: if this Send requires email verification, retry with `--email ADDRESS`)"
                ))
            } else {
                Ok(out)
            }
        }).map_err(|err| match err {
            Error::User(msg) if !msg.contains("`--email`") => Error::user(format!(
                "{msg}\n(hint: if this Send requires email verification, retry with `--email ADDRESS`)"
            )),
            other => other,
        }),
        Some(email) => send_receive_gated(url, opts, email),
    }
}
fn send_args<'a>(
    url: &'a str,
    password_args: &'a [String],
    owned: &'a mut Vec<String>,
) -> Vec<&'a str> {
    for flag in password_args {
        owned.push(flag.clone());
    }
    let mut args: Vec<&str> = vec!["send", "receive", url];
    for flag in owned.iter() {
        args.push(flag.as_str());
    }
    args
}

fn send_receive_plain(url: &str, password_args: &[String]) -> Result<Vec<u8>, Error> {
    let bw = require_bw()?;
    let mut owned = Vec::new();
    let args = send_args(url, password_args, &mut owned);
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

/// What bw is currently asking for, detected from its cleaned stderr.
/// Checked in this order because the code prompt also mentions email.
#[derive(Debug, PartialEq, Eq)]
enum PromptAction {
    SendEmail,
    SendCode,
    PasswordNeeded,
    EmailRejected,
    Wait,
}

fn decide_action(log: &str, email_sent: bool, code_sent: bool, email_stale: bool) -> PromptAction {
    if log.contains("password") && log.contains("enter") {
        return PromptAction::PasswordNeeded;
    }
    if !code_sent && log.contains("verification code") {
        return PromptAction::SendCode;
    }
    if email_sent {
        if !code_sent && email_stale && log.contains("email") {
            return PromptAction::EmailRejected;
        }
        return PromptAction::Wait;
    }
    if log.contains("email") {
        return PromptAction::SendEmail;
    }
    PromptAction::Wait
}

/// Strip inquirer-style ANSI redraws (`ESC[2K`, `ESC[28D`, ...) so prompt
/// markers match. Carriage returns become newlines.
fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.next() {
                Some('[') => {
                    for c2 in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&c2) {
                            break;
                        }
                    }
                }
                // Other escape sequences: drop the introducer too.
                Some(_) => {}
                None => {}
            }
            continue;
        }
        if c == '\r' {
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    out
}

/// A verification code is 4-8 ASCII digits and nothing else. The error
/// never echoes the input: hook output may be a whole mailbox dump.
fn validate_code(raw: &str) -> Result<String, Error> {
    let code = raw.trim();
    if (4..=8).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_digit()) {
        Ok(code.to_string())
    } else {
        Err(Error::user(format!(
            "verification code must be 4-8 digits, got {} chars of non-conforming output",
            code.len()
        )))
    }
}

/// Obtain the code from env/file/hook/terminal. Hook output must be ONLY
/// the code (the hook owns "newest" semantics); it is polled until the
/// deadline because the code email may lag behind the prompt.
///
/// `seen` holds hook outputs observed before the fresh code could exist
/// (seeded pre-mint, then accumulated): codes are minted per attempt, so
/// anything already seen is stale and must be skipped, never submitted.
/// Without this, the first poll would instantly return yesterday's code.
fn obtain_code(
    opts: &SendReceiveOptions,
    email: &str,
    deadline: Instant,
    seen: &mut std::collections::HashSet<String>,
) -> Result<String, Error> {
    if let Some(var) = &opts.code_env {
        let raw =
            std::env::var(var).map_err(|_| Error::user(format!("env var `{var}` is not set")))?;
        return validate_code(&raw);
    }
    if let Some(path) = &opts.code_file {
        let raw = std::fs::read_to_string(path)
            .map_err(|err| Error::user(format!("cannot read code file: {err}")))?;
        return validate_code(&raw);
    }
    if let Some(cmd) = &opts.code_cmd {
        loop {
            let output = Command::new("sh")
                .args(["-c", cmd])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .map_err(|err| Error::user(format!("code hook failed to run: {err}")))?;
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            // Skip anything predating this attempt; remember everything seen
            // so a flapping listing cannot resubmit a stale code either.
            if !text.is_empty() {
                if !seen.insert(text.clone()) {
                    // Already seen: stale by construction, keep waiting.
                } else if let Ok(code) = validate_code(&text) {
                    return Ok(code);
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::user(format!(
                    "timed out waiting for the code hook to print a fresh 4-8 digit code (hook: `{cmd}`); \
                     the hook must print ONLY the newest code"
                )));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(remaining.min(opts.poll_interval()));
        }
    }
    prompt_tty(email)
}

/// Interactive fallback for humans: ask on /dev/tty so `--json` stdout
/// stays machine-readable. Agents must use a code source flag instead.
fn prompt_tty(email: &str) -> Result<String, Error> {
    use std::io::{BufRead, Write};
    let no_tty = || {
        Error::user(
            "no --code-cmd/--codeenv/--codefile given and no terminal to ask on; \
             rerun with one of those flags (agents: --code-cmd)",
        )
    };
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| no_tty())?;
    let mut tty = std::io::BufReader::new(try_clone_tty(&tty)?);
    writeln!(
        tty.get_mut(),
        "hush: Bitwarden sent a verification code to {email}; enter it:"
    )
    .map_err(|_| no_tty())?;
    let mut line = String::new();
    tty.read_line(&mut line).map_err(|_| no_tty())?;
    validate_code(&line)
}

fn try_clone_tty(tty: &std::fs::File) -> Result<std::fs::File, Error> {
    tty.try_clone()
        .map_err(|_| Error::user("cannot use terminal for code prompt"))
}

/// Drive bw's email/code prompts over pipes. The secret travels
/// bw-stdout -> hush memory -> vault; prompts, email and code never do.
fn send_receive_gated(url: &str, opts: &SendReceiveOptions, email: &str) -> Result<Vec<u8>, Error> {
    use std::io::Write;

    let bw = require_bw()?;
    let mut owned = Vec::new();
    let args = send_args(url, &opts.password_args, &mut owned);
    let mut child = Command::new(&bw)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take();
    let stdout_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let log_buf = Arc::new(Mutex::new(String::new()));
    let mut stdout_handle = child.stdout.take().map(|mut out| {
        let buf = Arc::clone(&stdout_buf);
        std::thread::spawn(move || {
            use std::io::Read;
            let mut chunk = [0u8; 8192];
            loop {
                match out.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf
                        .lock()
                        .expect("stdout buf")
                        .extend_from_slice(&chunk[..n]),
                }
            }
        })
    });
    let mut stderr_handle = child.stderr.take().map(|mut err| {
        let buf = Arc::clone(&log_buf);
        std::thread::spawn(move || {
            use std::io::Read;
            let mut chunk = [0u8; 4096];
            loop {
                match err.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let cleaned =
                            strip_ansi(&String::from_utf8_lossy(&chunk[..n])).to_lowercase();
                        let mut log = buf.lock().expect("stderr buf");
                        log.push_str(&cleaned);
                        // Bound memory: prompts live at the tail.
                        const MAX_LOG: usize = 32 * 1024;
                        if log.len() > MAX_LOG {
                            let drop = log.len() - MAX_LOG;
                            log.drain(..drop);
                        }
                    }
                }
            }
        })
    });

    let deadline = Instant::now() + opts.timeout();
    let mut email_sent_at: Option<Instant> = None;
    let mut code_sent = false;
    // Snapshot the hook BEFORE bw mints a code: whatever it prints now
    // predates this attempt and must never be submitted.
    let mut seen_codes = std::collections::HashSet::new();
    if let Some(cmd) = &opts.code_cmd {
        if let Ok(output) = Command::new("sh")
            .args(["-c", cmd])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            let pre = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !pre.is_empty() {
                seen_codes.insert(pre);
            }
        }
    }
    // If bw re-asks for the email 10s after we sent it, the address was rejected.
    let email_grace = Duration::from_secs(10);
    let exit = loop {
        if Instant::now() >= deadline {
            let _ = child.kill();
            return finish_gated(
                &mut child,
                &mut stdout_handle,
                &mut stderr_handle,
                &stdout_buf,
                &log_buf,
                Err(Error::user(
                    "timed out waiting for Bitwarden email verification; retry `hush pull` for a fresh code (see --code-timeout)".to_string()
                )),
            );
        }
        if let Some(status) = child.try_wait()? {
            break Ok(status);
        }
        let log = log_buf.lock().expect("stderr buf").clone();
        let email_stale = email_sent_at.is_some_and(|t| t.elapsed() > email_grace);
        match decide_action(&log, email_sent_at.is_some(), code_sent, email_stale) {
            PromptAction::PasswordNeeded => {
                let _ = child.kill();
                return finish_gated(
                    &mut child,
                    &mut stdout_handle,
                    &mut stderr_handle,
                    &stdout_buf,
                    &log_buf,
                    Err(Error::user(
                        "bw asks for a Send password interactively; rerun with --passwordenv VAR or --passwordfile PATH",
                    )),
                );
            }
            PromptAction::EmailRejected => {
                let _ = child.kill();
                return finish_gated(
                    &mut child,
                    &mut stdout_handle,
                    &mut stderr_handle,
                    &stdout_buf,
                    &log_buf,
                    Err(Error::user(format!(
                        "Bitwarden kept asking for the email address; `{email}` is not authorized for this Send"
                    ))),
                );
            }
            PromptAction::SendEmail => {
                let mut failed = false;
                if let Some(input) = stdin.as_mut() {
                    if writeln!(input, "{email}").is_err() {
                        failed = true;
                    }
                }
                if failed {
                    break Err(Error::user("bw closed stdin while asking for email"));
                }
                email_sent_at = Some(Instant::now());
            }
            PromptAction::SendCode => {
                let code = match obtain_code(opts, email, deadline, &mut seen_codes) {
                    Ok(code) => code,
                    Err(err) => {
                        let _ = child.kill();
                        return finish_gated(
                            &mut child,
                            &mut stdout_handle,
                            &mut stderr_handle,
                            &stdout_buf,
                            &log_buf,
                            Err(err),
                        );
                    }
                };
                let mut failed = false;
                if let Some(input) = stdin.as_mut() {
                    if writeln!(input, "{code}").is_err() {
                        failed = true;
                    }
                }
                if failed {
                    break Err(Error::user("bw closed stdin while asking for the code"));
                }
                code_sent = true;
            }
            PromptAction::Wait => {}
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    // Let bw see EOF once answered; a live child ignores a closed stdin here.
    drop(stdin);
    match exit {
        Err(err) => {
            let _ = child.kill();
            finish_gated(
                &mut child,
                &mut stdout_handle,
                &mut stderr_handle,
                &stdout_buf,
                &log_buf,
                Err(err),
            )
        }
        Ok(_) => finish_gated(
            &mut child,
            &mut stdout_handle,
            &mut stderr_handle,
            &stdout_buf,
            &log_buf,
            Ok(()),
        ),
    }
}

/// Reap the child, join pump threads, then report stdout or a mapped error.
/// `early_err` short-circuits with a driver-side error (timeout, rejected
/// address) instead of bw's own exit text.
fn finish_gated(
    child: &mut std::process::Child,
    stdout_handle: &mut Option<std::thread::JoinHandle<()>>,
    stderr_handle: &mut Option<std::thread::JoinHandle<()>>,
    stdout_buf: &Arc<Mutex<Vec<u8>>>,
    log_buf: &Arc<Mutex<String>>,
    early_err: Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    let status = child.wait();
    if let Some(handle) = stdout_handle.take() {
        let _ = handle.join();
    }
    if let Some(handle) = stderr_handle.take() {
        let _ = handle.join();
    }
    early_err?;
    let status = status?;
    if status.success() {
        let out = stdout_buf.lock().expect("stdout buf").clone();
        if out.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(Error::user(
                "bw returned empty output for an email-verified Send",
            ));
        }
        return Ok(out);
    }
    let log = log_buf.lock().expect("stderr buf").clone();
    if log.contains("invalid") && log.contains("code") {
        return Err(Error::user(
            "Bitwarden rejected the verification code (codes are single-use and minted per attempt); \
             retry `hush pull` for a fresh code and submit the newest one",
        ));
    }
    let tail: String = log
        .chars()
        .rev()
        .take(500)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    Err(Error::user(format!(
        "bw send receive failed: {}",
        tail.trim()
    )))
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

    #[test]
    fn strips_inquirer_redraws() {
        let raw = "? Enter your email address: \x1b[28D\x1b[28C\x1b[2K\x1b[G? Enter the verification code sent to your email: \x1b[50D\x1b[50C";
        let cleaned = strip_ansi(raw).to_lowercase();
        assert!(cleaned.contains("enter your email address"));
        assert!(cleaned.contains("verification code"));
        assert!(!cleaned.contains('\x1b'));
    }

    #[test]
    fn decides_prompt_actions_in_order() {
        use PromptAction::*;
        // Code prompt mentions email too: code wins.
        assert_eq!(
            decide_action(
                "enter the verification code sent to your email",
                false,
                false,
                false
            ),
            SendCode
        );
        assert_eq!(
            decide_action("enter your email address", false, false, false),
            SendEmail
        );
        // Already answered: wait, unless bw keeps asking for a rejected email.
        assert_eq!(
            decide_action("enter your email address", true, false, false),
            Wait
        );
        assert_eq!(
            decide_action("enter your email address", true, false, true),
            EmailRejected
        );
        assert_eq!(
            decide_action("enter the send password", false, false, false),
            PasswordNeeded
        );
        assert_eq!(decide_action("syncing complete", false, false, false), Wait);
    }

    #[test]
    fn validates_codes_strictly_without_echoing() {
        assert_eq!(validate_code("827126").unwrap(), "827126");
        assert_eq!(validate_code("  827126\n").unwrap(), "827126");
        for bad in ["123", "123456789", "abc123", "12 34"] {
            let err = validate_code(bad).unwrap_err().to_string();
            assert!(err.contains("4-8 digits"), "{err}");
            assert!(!err.contains(bad.trim()), "error must not echo input");
        }
        assert!(validate_code("").is_err());
        assert!(validate_code("   \n").is_err());
    }

    #[test]
    fn polls_hook_until_code_appears() {
        let dir = tempfile::TempDir::new().unwrap();
        let counter = dir.path().join("n");
        let hook = format!(
            "n=$(cat {} 2>/dev/null || echo 0); echo $((n+1)) > {}; if [ \"$n\" -ge 2 ]; then echo 424242; fi",
            counter.display(),
            counter.display()
        );
        let opts = SendReceiveOptions {
            code_cmd: Some(hook),
            code_poll_secs: 1,
            code_timeout_secs: 30,
            ..SendReceiveOptions::default()
        };
        let mut seen = std::collections::HashSet::new();
        let code = obtain_code(
            &opts,
            "a@b.c",
            Instant::now() + Duration::from_secs(30),
            &mut seen,
        )
        .unwrap();
        assert_eq!(code, "424242");
    }

    #[test]
    fn skips_previously_seen_codes() {
        // The hook keeps returning yesterday's code: it must be skipped,
        // never submitted, until the deadline.
        let mut seen = std::collections::HashSet::new();
        seen.insert("111111".to_string());
        let opts = SendReceiveOptions {
            code_cmd: Some("echo 111111".into()),
            code_poll_secs: 1,
            code_timeout_secs: 3,
            ..SendReceiveOptions::default()
        };
        let err = obtain_code(
            &opts,
            "a@b.c",
            Instant::now() + Duration::from_secs(3),
            &mut seen,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("timed out"), "{err}");
    }

    #[test]
    fn hook_timeout_is_actionable() {
        let opts = SendReceiveOptions {
            code_cmd: Some("true".into()),
            code_poll_secs: 1,
            code_timeout_secs: 3,
            ..SendReceiveOptions::default()
        };
        let mut seen = std::collections::HashSet::new();
        let err = obtain_code(
            &opts,
            "a@b.c",
            Instant::now() + Duration::from_secs(3),
            &mut seen,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("timed out"), "{err}");
        assert!(!err.contains("424242"));
    }
}
