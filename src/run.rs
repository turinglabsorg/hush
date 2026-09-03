use std::ffi::OsStr;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

use crate::name::parse_env_name;
use crate::paths::Paths;
use crate::vault::Vault;
use crate::Error;

/// Env vars that grant access to secret stores. They are never inherited by
/// the child: the child receives secrets ONLY through the injected `--env`
/// variable. Without this, a child shell could read `BW_SESSION` (or the
/// Bitwarden profile dir) and call `bw` directly, bypassing hush.
const SCRUBBED_ENV_VARS: &[&str] = &[
    "BW_SESSION",
    "BW_CLIENTID",
    "BW_CLIENTSECRET",
    "BW_PASSWORD",
    "BITWARDENCLI_APPDATA_DIR",
];

pub const REDACTED: &str = "[redacted by hush]";

pub fn run(
    paths: &Paths,
    name: &str,
    env_name: &str,
    command: &[String],
    redact: bool,
) -> Result<(), Error> {
    if command.is_empty() {
        return Err(Error::user("missing command after `--`"));
    }
    let env_name = parse_env_name(env_name)?;
    let vault = Vault::open(paths)?;
    let secret = vault.get(name)?;
    let secret_str = std::str::from_utf8(&secret).map_err(|_| {
        Error::user("secret is not valid UTF-8; hush run only injects text secrets")
    })?;
    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    for var in SCRUBBED_ENV_VARS {
        child.env_remove(var);
    }
    child.env(&env_name, OsStr::new(secret_str));
    if redact {
        return run_redacted(&mut child, secret_str.as_bytes());
    }
    child.stdin(Stdio::inherit());
    child.stdout(Stdio::inherit());
    child.stderr(Stdio::inherit());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = child.exec();
        Err(err.into())
    }

    #[cfg(not(unix))]
    {
        let status = child.status()?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::CommandFailed(command[0].clone(), status))
        }
    }
}

/// Spawn the child with piped stdio and replace every occurrence of the
/// secret in its output with `[redacted by hush]`. Agents should always use
/// this mode: a command that echoes its own input would otherwise leak the
/// secret into the transcript.
fn run_redacted(child: &mut Command, secret: &[u8]) -> Result<(), Error> {
    let mut spawned = child
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = spawned.stdout.take();
    let mut stderr = spawned.stderr.take();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            if let Some(out) = stdout.as_mut() {
                pump_redacted(out, &StdoutTarget, secret);
            }
        });
        scope.spawn(|| {
            if let Some(err) = stderr.as_mut() {
                pump_redacted(err, &StderrTarget, secret);
            }
        });
    });
    let status = spawned.wait()?;
    if status.success() {
        Ok(())
    } else {
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Stream `reader` to stdout/stderr with secret occurrences redacted.
/// The target (stdout vs stderr) is selected by the caller.
fn pump_redacted<R: Read>(reader: &mut R, writer: &impl WriteTarget, secret: &[u8]) {
    let mut redactor = Redactor::new(secret);
    let mut buf = [0u8; 8192];
    let mut handle = writer.lock();
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let safe = redactor.push(&buf[..n]);
                if handle.write_all(&safe).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let tail = redactor.finish();
    let _ = handle.write_all(&tail);
}

trait WriteTarget {
    type Handle<'a>: Write
    where
        Self: 'a;
    fn lock(&self) -> Self::Handle<'_>;
}

struct StdoutTarget;
struct StderrTarget;

impl WriteTarget for StdoutTarget {
    type Handle<'a> = std::io::StdoutLock<'a>;
    fn lock(&self) -> Self::Handle<'_> {
        std::io::stdout().lock()
    }
}

impl WriteTarget for StderrTarget {
    type Handle<'a> = std::io::StderrLock<'a>;
    fn lock(&self) -> Self::Handle<'_> {
        std::io::stderr().lock()
    }
}

/// Streaming byte replacer. Holds back up to `secret.len() - 1` trailing
/// bytes so matches split across chunk boundaries are still caught.
pub struct Redactor {
    secret: Vec<u8>,
    tail: Vec<u8>,
}

impl Redactor {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            tail: Vec::new(),
        }
    }

    /// Feed a chunk; returns the prefix that is safe to emit.
    /// A match straddling the emit boundary is held back whole, so it can
    /// never leak half-replaced into the output.
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        if self.secret.is_empty() {
            return data.to_vec();
        }
        let mut buf = std::mem::take(&mut self.tail);
        buf.extend_from_slice(data);
        let hold = self.secret.len().saturating_sub(1);
        let split = buf.len().saturating_sub(hold);
        let mut emit_end = split;
        let mut pos = 0;
        while pos < split {
            match find_subslice(&buf[pos..], &self.secret) {
                Some(rel) => {
                    let start = pos + rel;
                    if start >= split {
                        break;
                    }
                    if start + self.secret.len() > split {
                        emit_end = start;
                        break;
                    }
                    pos = start + self.secret.len();
                }
                None => break,
            }
        }
        let tail = buf.split_off(emit_end);
        self.tail = tail;
        replace_all(&buf, &self.secret, REDACTED.as_bytes())
    }

    /// Flush remaining bytes with replacement applied.
    pub fn finish(mut self) -> Vec<u8> {
        if self.secret.is_empty() {
            return std::mem::take(&mut self.tail);
        }
        let tail = std::mem::take(&mut self.tail);
        replace_all(&tail, &self.secret, REDACTED.as_bytes())
    }
}

fn replace_all(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut rest = haystack;
    while let Some(pos) = find_subslice(rest, needle) {
        out.extend_from_slice(&rest[..pos]);
        out.extend_from_slice(replacement);
        rest = &rest[pos + needle.len()..];
    }
    out.extend_from_slice(rest);
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_simple_occurrences() {
        let mut r = Redactor::new(b"secret");
        assert_eq!(r.push(b"a secret b secret c"), b"a [redacted by hush] b ");
        assert_eq!(r.finish(), b"[redacted by hush] c");
    }

    #[test]
    fn catches_split_boundaries() {
        let mut r = Redactor::new(b"abcdef");
        let a = r.push(b"xxabc");
        let b = r.push(b"defyy");
        let mut out = a;
        out.extend(b);
        out.extend(r.finish());
        assert_eq!(out, b"xx[redacted by hush]yy");
    }

    #[test]
    fn catches_match_split_across_emit_boundary() {
        // "secret" #2 spans the emit boundary; it must be held back whole,
        // never emitted half-replaced.
        let mut r = Redactor::new(b"secret");
        let a = r.push(b"a secret b secret c");
        let mut out = a;
        out.extend(r.finish());
        assert_eq!(out, b"a [redacted by hush] b [redacted by hush] c");
        assert!(!out.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn single_byte_secret() {
        let mut r = Redactor::new(b"x");
        assert_eq!(r.push(b"axb"), b"a[redacted by hush]b");
        assert_eq!(r.finish(), b"");
    }

    #[test]
    fn empty_secret_passes_through() {
        let mut r = Redactor::new(b"");
        assert_eq!(r.push(b"data"), b"data");
        assert_eq!(r.finish(), b"");
    }

    #[test]
    fn no_match_passes_through() {
        let mut r = Redactor::new(b"zzz");
        // Streaming always holds back len(secret)-1 bytes for a possible
        // split match; they flush on finish.
        assert_eq!(r.push(b"hello world"), b"hello wor");
        assert_eq!(r.finish(), b"ld");
    }
}
