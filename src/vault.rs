use std::fs;
use std::io::{Read, Write};
use std::str::FromStr;

use age::x25519::Identity;
use age::{Decryptor, Encryptor};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::name::parse_name;
use crate::paths::Paths;
use crate::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    pub created: String,
    pub updated: String,
    pub source: String,
    pub sender: String,
    pub bytes: usize,
}

pub struct Vault {
    paths: Paths,
    identity: Identity,
}

impl Vault {
    pub fn init(paths: &Paths) -> Result<Self, Error> {
        if paths.identity_file().exists() {
            return Err(Error::AlreadyInitialized);
        }
        paths.ensure_layout()?;
        let identity = Identity::generate();
        crate::paths::atomic_write(
            &paths.identity_file(),
            identity.to_string().expose_secret().as_bytes(),
        )?;
        let vault = Self::open(paths)?;
        Ok(vault)
    }

    pub fn open(paths: &Paths) -> Result<Self, Error> {
        let identity_path = paths.identity_file();
        if !identity_path.exists() {
            return Err(Error::NotInitialized);
        }
        let raw = Zeroizing::new(fs::read_to_string(&identity_path)?);
        let identity =
            Identity::from_str(raw.trim()).map_err(|err| Error::Decrypt(err.to_string()))?;
        Ok(Self {
            paths: paths.clone(),
            identity,
        })
    }

    pub fn put(&self, name: &str, value: &[u8], source: &str, sender: &str) -> Result<Meta, Error> {
        let name = parse_name(name)?;
        let now = now_rfc3339();
        let existing = self.read_meta(&name).ok();
        let created = existing
            .as_ref()
            .map(|meta| meta.created.clone())
            .unwrap_or_else(|| now.clone());
        let ciphertext = encrypt(&self.identity, value)?;
        crate::paths::atomic_write(&self.paths.secret_file(&name), &ciphertext)?;
        let meta = Meta {
            name: name.clone(),
            created,
            updated: now,
            source: source.to_string(),
            sender: sender.to_string(),
            bytes: value.len(),
        };
        let raw = serde_json::to_vec_pretty(&meta)?;
        crate::paths::atomic_write(&self.paths.meta_file(&name), &raw)?;
        Ok(meta)
    }

    pub fn get(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        let name = parse_name(name)?;
        let path = self.paths.secret_file(&name);
        if !path.exists() {
            return Err(Error::NotFound(name));
        }
        let ciphertext = fs::read(path)?;
        decrypt(&self.identity, &ciphertext)
    }

    pub fn info(&self, name: &str) -> Result<Meta, Error> {
        let name = parse_name(name)?;
        self.read_meta(&name)
    }

    pub fn list(&self) -> Result<Vec<Meta>, Error> {
        let mut items = Vec::new();
        let dir = self.paths.vault_dir();
        if !dir.exists() {
            return Ok(items);
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(name) = file_name.strip_suffix(".meta.json") else {
                continue;
            };
            if let Ok(meta) = self.read_meta(name) {
                items.push(meta);
            }
        }
        items.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(items)
    }

    pub fn remove(&self, name: &str) -> Result<(), Error> {
        let name = parse_name(name)?;
        let secret = self.paths.secret_file(&name);
        let meta = self.paths.meta_file(&name);
        if !secret.exists() && !meta.exists() {
            return Err(Error::NotFound(name));
        }
        if secret.exists() {
            fs::remove_file(secret)?;
        }
        if meta.exists() {
            fs::remove_file(meta)?;
        }
        Ok(())
    }

    fn read_meta(&self, name: &str) -> Result<Meta, Error> {
        let path = self.paths.meta_file(name);
        if !path.exists() {
            return Err(Error::NotFound(name.to_string()));
        }
        let raw = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn encrypt(identity: &Identity, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let recipient = identity.to_public();
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|err| Error::Encrypt(err.to_string()))?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|err| Error::Encrypt(err.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|err| Error::Encrypt(err.to_string()))?;
    writer
        .finish()
        .map_err(|err| Error::Encrypt(err.to_string()))?;
    Ok(ciphertext)
}

fn decrypt(identity: &Identity, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let decryptor = Decryptor::new(ciphertext).map_err(|err| Error::Decrypt(err.to_string()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|err| Error::Decrypt(err.to_string()))?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plaintext)
        .map_err(|err| Error::Decrypt(err.to_string()))?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_paths() -> (TempDir, Paths) {
        let dir = TempDir::new().unwrap();
        let paths = Paths::new(dir.path().join("hush"));
        (dir, paths)
    }

    #[test]
    fn round_trip_and_overwrite() {
        let (_tmp, paths) = tmp_paths();
        Vault::init(&paths).unwrap();
        let vault = Vault::open(&paths).unwrap();
        vault
            .put("stripe-prod", b"first", "signal", "self")
            .unwrap();
        vault
            .put("stripe-prod", b"second", "signal", "self")
            .unwrap();
        let value = vault.get("stripe-prod").unwrap();
        assert_eq!(&value[..], b"second");
        let listed = vault.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].bytes, 6);
        vault.remove("stripe-prod").unwrap();
        assert!(vault.get("stripe-prod").is_err());
    }

    #[test]
    fn ciphertext_is_not_plaintext() {
        let (_tmp, paths) = tmp_paths();
        Vault::init(&paths).unwrap();
        let vault = Vault::open(&paths).unwrap();
        vault
            .put("token", b"super-secret-value", "signal", "self")
            .unwrap();
        let raw = fs::read(paths.secret_file("token")).unwrap();
        let as_text = String::from_utf8_lossy(&raw);
        assert!(!as_text.contains("super-secret-value"));
    }
}
