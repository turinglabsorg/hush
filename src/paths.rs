use std::fs;
use std::path::{Path, PathBuf};

use crate::Error;

#[derive(Clone, Debug)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn from_env() -> Self {
        if let Some(home) = std::env::var_os("HUSH_HOME") {
            return Self::new(PathBuf::from(home));
        }
        let root = std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join(".hush"))
            .unwrap_or_else(|| PathBuf::from(".hush"));
        Self::new(root)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.json")
    }

    pub fn identity_file(&self) -> PathBuf {
        self.root.join("identity")
    }

    pub fn vault_dir(&self) -> PathBuf {
        self.root.join("vault")
    }

    pub fn secret_file(&self, name: &str) -> PathBuf {
        self.vault_dir().join(format!("{name}.age"))
    }

    pub fn meta_file(&self, name: &str) -> PathBuf {
        self.vault_dir().join(format!("{name}.meta.json"))
    }

    pub fn ensure_layout(&self) -> Result<(), Error> {
        fs::create_dir_all(&self.root)?;
        fs::create_dir_all(self.vault_dir())?;
        set_dir_private(&self.root)?;
        set_dir_private(&self.vault_dir())?;
        Ok(())
    }
}

pub fn set_dir_private(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn set_file_private(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    set_file_private(&tmp)?;
    fs::rename(&tmp, path)?;
    set_file_private(path)?;
    Ok(())
}
