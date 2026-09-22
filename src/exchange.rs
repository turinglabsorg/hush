//! Long payloads between two hush installs.
//!
//! Signal text is a poor pipe past about 1000 characters, and RSA-OAEP can only
//! wrap a short key. The body is AES-256-GCM. The recipient's RSA public key
//! wraps that key. The directory stores public keys only.

use std::fs;
use std::io::{Read, Write};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::pss::BlindedSigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::name::parse_box_address;
use crate::paths::{atomic_write, Paths};
use crate::vault::Vault;
use crate::Error;

pub const ALG: &str = "RSA-OAEP-SHA256+AES-256-GCM";
pub const SIGNED_PREFIX: &str = "hush-box-v1";

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    v: u32,
    alg: String,
    to: String,
    ek: String,
    nonce: String,
    ct: String,
}

pub fn signed_message(name: &str, public_key_pem: &str) -> Vec<u8> {
    format!("{SIGNED_PREFIX}\n{name}\n{public_key_pem}").into_bytes()
}

pub fn init(paths: &Paths) -> Result<(), Error> {
    if paths.box_key_file().exists() {
        return Err(Error::user("box key already exists"));
    }
    paths.ensure_layout()?;
    let mut rng = OsRng;
    let private =
        RsaPrivateKey::new(&mut rng, 2048).map_err(|err| Error::Encrypt(err.to_string()))?;
    let public = RsaPublicKey::from(&private);
    let private_pem = private
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|err| Error::Encrypt(err.to_string()))?;
    let public_pem = public
        .to_public_key_pem(LineEnding::LF)
        .map_err(|err| Error::Encrypt(err.to_string()))?;
    atomic_write(&paths.box_key_file(), private_pem.as_bytes())?;
    atomic_write(&paths.box_pub_file(), public_pem.as_bytes())?;
    println!("box key {}", paths.box_key_file().display());
    println!("public key {}", paths.box_pub_file().display());
    Ok(())
}

pub fn seal_to_pem(plaintext: &[u8], to: &str, public_pem: &str) -> Result<Vec<u8>, Error> {
    let to = parse_box_address(to)?;
    let public = RsaPublicKey::from_public_key_pem(public_pem.trim())
        .map_err(|err| Error::Encrypt(err.to_string()))?;
    let mut rng = OsRng;
    let mut raw_key = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(raw_key.as_mut());
    let mut raw_nonce = [0u8; 12];
    rng.fill_bytes(&mut raw_nonce);

    let cipher = Aes256Gcm::new_from_slice(raw_key.as_ref())
        .map_err(|err| Error::Encrypt(err.to_string()))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&raw_nonce), plaintext)
        .map_err(|err| Error::Encrypt(err.to_string()))?;
    let wrapped = public
        .encrypt(&mut rng, Oaep::new::<Sha256>(), raw_key.as_ref())
        .map_err(|err| Error::Encrypt(err.to_string()))?;

    let envelope = Envelope {
        v: 1,
        alg: ALG.to_string(),
        to,
        ek: STANDARD.encode(wrapped),
        nonce: STANDARD.encode(raw_nonce),
        ct: STANDARD.encode(ciphertext),
    };
    Ok(serde_json::to_vec(&envelope)?)
}

pub fn open_with_pem(
    envelope_bytes: &[u8],
    private_pem: &str,
) -> Result<(String, Zeroizing<Vec<u8>>), Error> {
    let envelope: Envelope = serde_json::from_slice(envelope_bytes)?;
    if envelope.v != 1 || envelope.alg != ALG {
        return Err(Error::Decrypt("unsupported box envelope".into()));
    }
    let private = RsaPrivateKey::from_pkcs8_pem(private_pem.trim())
        .map_err(|err| Error::Decrypt(err.to_string()))?;
    let wrapped = STANDARD
        .decode(envelope.ek.trim())
        .map_err(|err| Error::Decrypt(err.to_string()))?;
    let nonce = STANDARD
        .decode(envelope.nonce.trim())
        .map_err(|err| Error::Decrypt(err.to_string()))?;
    let ciphertext = STANDARD
        .decode(envelope.ct.trim())
        .map_err(|err| Error::Decrypt(err.to_string()))?;
    let raw_key = Zeroizing::new(
        private
            .decrypt(Oaep::new::<Sha256>(), &wrapped)
            .map_err(|err| Error::Decrypt(err.to_string()))?,
    );
    let cipher = Aes256Gcm::new_from_slice(raw_key.as_ref())
        .map_err(|err| Error::Decrypt(err.to_string()))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| Error::Decrypt("authentication failed".into()))?;
    Ok((envelope.to, Zeroizing::new(plain)))
}

pub fn sign_publish(private_pem: &str, name: &str, public_pem: &str) -> Result<String, Error> {
    let private = RsaPrivateKey::from_pkcs8_pem(private_pem.trim())
        .map_err(|err| Error::Encrypt(err.to_string()))?;
    let signer = BlindedSigningKey::<Sha256>::new(private);
    let sig = signer.sign_with_rng(&mut OsRng, &signed_message(name, public_pem));
    Ok(STANDARD.encode(sig.to_bytes()))
}

fn read_private_pem(paths: &Paths) -> Result<String, Error> {
    let path = paths.box_key_file();
    if !path.exists() {
        return Err(Error::user("no box key; run `hush box init`"));
    }
    Ok(fs::read_to_string(path)?)
}

fn read_public_pem(paths: &Paths) -> Result<String, Error> {
    let path = paths.box_pub_file();
    if !path.exists() {
        return Err(Error::user("no box public key; run `hush box init`"));
    }
    Ok(fs::read_to_string(path)?)
}

pub const PUBLIC_DIRECTORY: &str = "https://hush-directory-828110571677.europe-west1.run.app";

pub fn directory_url() -> Result<String, Error> {
    Ok(std::env::var("HUSH_DIRECTORY_URL")
        .ok()
        .map(|url| url.trim_end_matches('/').to_string())
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| PUBLIC_DIRECTORY.to_string()))
}

pub fn register(paths: &Paths, address: &str) -> Result<(), Error> {
    let address = parse_box_address(address)?;
    if !paths.box_key_file().exists() {
        init(paths)?;
    }
    publish(paths, &address)
}

pub fn publish(paths: &Paths, name: &str) -> Result<(), Error> {
    let name = parse_box_address(name)?;
    let private_pem = read_private_pem(paths)?;
    let public_pem = read_public_pem(paths)?;
    let signature = sign_publish(&private_pem, &name, &public_pem)?;
    let url = format!("{}/v1/keys/{}", directory_url()?, encode_address(&name));
    let response = ureq::put(&url)
        .set("content-type", "application/json")
        .send_json(serde_json::json!({
            "public_key_pem": public_pem,
            "signature_b64": signature,
        }))
        .map_err(|err| Error::user(format!("directory publish failed: {err}")))?;
    if !(200..300).contains(&response.status()) {
        return Err(Error::user(format!(
            "directory publish failed: HTTP {}",
            response.status()
        )));
    }
    println!("published {name}");
    Ok(())
}

fn encode_address(name: &str) -> String {
    name.bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

pub fn fetch_public_key(name: &str) -> Result<String, Error> {
    let name = parse_box_address(name)?;
    let url = format!("{}/v1/keys/{}", directory_url()?, encode_address(&name));
    let response = ureq::get(&url)
        .call()
        .map_err(|err| Error::user(format!("directory lookup failed: {err}")))?;
    let body: serde_json::Value = response
        .into_json()
        .map_err(|err| Error::user(format!("directory lookup failed: {err}")))?;
    body.get("public_key_pem")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| Error::user(format!("directory has no public key for {name}")))
}

pub fn read_payload(file: Option<&std::path::Path>) -> Result<(Zeroizing<Vec<u8>>, Option<String>), Error> {
    let mut plaintext = Zeroizing::new(Vec::new());
    let filename = if let Some(path) = file {
        let mut handle = fs::File::open(path)?;
        handle.read_to_end(plaintext.as_mut())?;
        path.file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)
    } else {
        std::io::stdin().read_to_end(plaintext.as_mut())?;
        None
    };
    if plaintext.is_empty() {
        return Err(Error::user("box seal read an empty payload"));
    }
    if plaintext.len() > 32 * 1024 * 1024 {
        return Err(Error::user("box seal refuses payloads over 32 MiB"));
    }
    Ok((plaintext, filename))
}

pub fn publish_envelope(to: &str, uses: u32, envelope: &[u8], file: Option<&str>) -> Result<String, Error> {
    if uses == 0 {
        return Err(Error::user("box seal requires -u greater than 0"));
    }
    let to = parse_box_address(to)?;
    let envelope: serde_json::Value = serde_json::from_slice(envelope)?;
    let url = format!("{}/v1/boxes", directory_url()?);
    let response = ureq::post(&url)
        .set("content-type", "application/json")
        .send_json(serde_json::json!({
            "to": to,
            "uses": uses,
            "file": file,
            "envelope": envelope,
        }))
        .map_err(|err| Error::user(format!("directory publish failed: {err}")))?;
    if !(200..300).contains(&response.status()) {
        return Err(Error::user(format!(
            "directory publish failed: HTTP {}",
            response.status()
        )));
    }
    let body: serde_json::Value = response
        .into_json()
        .map_err(|err| Error::user(format!("directory publish failed: {err}")))?;
    body.get("id")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| Error::user("directory did not return an id"))
}

pub fn pull_envelope(id: &str) -> Result<(Vec<u8>, u32), Error> {
    if !id.chars().all(|ch| ch.is_ascii_hexdigit()) || id.len() < 16 {
        return Err(Error::user("box id is not valid"));
    }
    let url = format!("{}/v1/boxes/{id}/pull", directory_url()?);
    let response = ureq::post(&url)
        .set("content-type", "application/json")
        .send_bytes(b"{}")
        .map_err(|err| Error::user(format!("directory pull failed: {err}")))?;
    let body: serde_json::Value = response
        .into_json()
        .map_err(|err| Error::user(format!("directory pull failed: {err}")))?;
    let envelope = serde_json::to_vec(
        body.get("envelope")
            .ok_or_else(|| Error::user("directory pull returned no envelope"))?,
    )?;
    let uses_left = body
        .get("uses_left")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as u32;
    Ok((envelope, uses_left))
}

pub fn seal_output(to: &str, public_pem: &str, plaintext: &[u8], uses: u32, file: Option<&str>, publish: bool) -> Result<(), Error> {
    let envelope = seal_to_pem(plaintext, to, public_pem)?;
    if publish {
        let id = publish_envelope(to, uses, &envelope, file)?;
        println!(
            "{}",
            serde_json::json!({
                "event": "sealed",
                "id": id,
                "to": parse_box_address(to)?,
                "file": file,
                "bytes": plaintext.len(),
                "uses": uses,
            })
        );
        return Ok(());
    }
    std::io::stdout().write_all(&envelope)?;
    std::io::stdout().write_all(b"\n")?;
    Ok(())
}

pub fn open_id(paths: &Paths, id: &str, name: &str, out: Option<&std::path::Path>) -> Result<(), Error> {
    let (raw, uses_left) = pull_envelope(id)?;
    open_bytes(paths, &raw, name, out, Some(uses_left))
}

pub fn open_stdin(paths: &Paths, name: &str, out: Option<&std::path::Path>) -> Result<(), Error> {
    let mut raw = Vec::new();
    std::io::stdin().read_to_end(&mut raw)?;
    open_bytes(paths, &raw, name, out, None)
}

fn open_bytes(
    paths: &Paths,
    raw: &[u8],
    name: &str,
    out: Option<&std::path::Path>,
    uses_left: Option<u32>,
) -> Result<(), Error> {
    let private_pem = read_private_pem(paths)?;
    let (sender, plaintext) = open_with_pem(raw, &private_pem)?;
    if let Some(path) = out {
        atomic_write(path, plaintext.as_slice())?;
    }
    let meta = Vault::open(paths)?.put(name, plaintext.as_slice(), "box", &sender)?;
    println!(
        "{}",
        serde_json::json!({
            "event": "stored",
            "name": meta.name,
            "sender": meta.sender,
            "bytes": meta.bytes,
            "uses_left": uses_left,
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_longer_than_a_signal_text() {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = RsaPublicKey::from(&private);
        let public_pem = public.to_public_key_pem(LineEnding::LF).unwrap();
        let private_pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
        let mut plaintext = b"marker-secret-".to_vec();
        plaintext.extend(std::iter::repeat_n(b'x', 4000));
        let envelope = seal_to_pem(&plaintext, "bob", &public_pem).unwrap();
        let encoded = String::from_utf8(envelope.clone()).unwrap();
        assert!(plaintext.len() > 1000);
        assert!(!encoded.contains("marker-secret-"));
        let (to, opened) = open_with_pem(&envelope, private_pem.as_ref()).unwrap();
        assert_eq!(to, "bob@hush.sh");
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn rejects_a_tampered_body() {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_pem = RsaPublicKey::from(&private)
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let private_pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
        let mut envelope = seal_to_pem(b"hello", "bob", &public_pem).unwrap();
        let last = envelope.len() - 2;
        envelope[last] ^= 0x01;
        assert!(open_with_pem(&envelope, private_pem.as_ref()).is_err());
    }
}
