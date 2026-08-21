use std::ffi::OsStr;
use std::process::Command;

use crate::name::parse_env_name;
use crate::paths::Paths;
use crate::vault::Vault;
use crate::Error;

pub fn run(paths: &Paths, name: &str, env_name: &str, command: &[String]) -> Result<(), Error> {
    if command.is_empty() {
        return Err(Error::user("missing command after `--`"));
    }
    let env_name = parse_env_name(env_name)?;
    let vault = Vault::open(paths)?;
    let secret = vault.get(name)?;
    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    child.env(
        &env_name,
        OsStr::new(std::str::from_utf8(&secret).map_err(|_| {
            Error::user("secret is not valid UTF-8; hush run only injects text secrets")
        })?),
    );
    child.stdin(std::process::Stdio::inherit());
    child.stdout(std::process::Stdio::inherit());
    child.stderr(std::process::Stdio::inherit());

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
