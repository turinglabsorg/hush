use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{vault::Vault, Error, Paths};

const LIMIT: u64 = 128 * 1024;

#[derive(Serialize, Deserialize)]
struct Credential {
    version: u8,
    rp_id: String,
    origin: String,
    credential_id: String,
    user_handle: String,
    private_key: String,
    prf_key: String,
    pin_secret: String,
    registered: bool,
    counter: u32,
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.prf_key.zeroize();
    }
}

fn invalid() -> Error {
    Error::user("passkey request refused: invalid or unsupported options")
}
fn encode(value: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(value)
}
fn decode(value: &str) -> Result<Vec<u8>, Error> {
    let result = URL_SAFE_NO_PAD.decode(value).map_err(|_| invalid())?;
    if encode(&result) != value || result.len() > 4096 {
        return Err(invalid());
    }
    Ok(result)
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn origin(origin: &str, rp: &str) -> Result<String, Error> {
    let parsed = url::Url::parse(origin).map_err(|_| invalid())?;
    if parsed.host_str() != Some(rp)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
        || !(parsed.scheme() == "https"
            || (parsed.scheme() == "http" && matches!(rp, "localhost" | "127.0.0.1" | "[::1]")))
    {
        return Err(Error::user(
            "passkeys require an exact HTTPS origin/RP (HTTP loopback allowed)",
        ));
    }
    Ok(parsed.origin().ascii_serialization())
}
struct Lock(std::path::PathBuf);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn lock(paths: &Paths, name: &str) -> Result<Lock, Error> {
    let name = crate::name::parse_name(name)?;
    let path = paths.vault_dir().join(format!("{name}.passkey-lock"));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| Error::user("passkey is busy (or a previous session was interrupted)"))?;
    crate::paths::set_file_private(&path)?;
    Ok(Lock(path))
}
fn wipe(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values {
                wipe(value);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                wipe(value);
            }
        }
        _ => {}
    }
}
fn load(vault: &Vault, name: &str) -> Result<Credential, Error> {
    if vault.info(name)?.source != "passkey" {
        return Err(Error::user("stored name is not a passkey"));
    }
    let raw = vault.get(name)?;
    let value: Credential =
        serde_json::from_slice(&raw).map_err(|_| Error::user("invalid stored passkey"))?;
    if value.version != 1 {
        return Err(Error::user("unsupported stored passkey version"));
    }
    Ok(value)
}
fn store(vault: &Vault, name: &str, value: &Credential) -> Result<(), Error> {
    let raw = Zeroizing::new(serde_json::to_vec(value)?);
    vault.put(name, &raw, "passkey", &value.rp_id)?;
    Ok(())
}
fn verify_pin(vault: &Vault, name: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    if vault.info(name)?.source == "passkey" {
        return Err(Error::user("a passkey cannot be a verification secret"));
    }
    let expected = vault.get(name)?;
    if expected.len() < 8 {
        return Err(Error::user(
            "passkey verification secret requires at least eight bytes",
        ));
    }
    let supplied = Zeroizing::new(std::env::var("HUSH_PASSKEY_PIN").map_err(|_| {
        Error::user(
        "inject the verification secret with hush run --name PIN --env HUSH_PASSKEY_PIN --redact",
    )
    })?);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&expected).map_err(|_| invalid())?;
    mac.update(b"hush:passkey:verification:v1");
    let tag = mac.finalize().into_bytes();
    let mut check =
        <Hmac<Sha256> as Mac>::new_from_slice(supplied.as_bytes()).map_err(|_| invalid())?;
    check.update(b"hush:passkey:verification:v1");
    check
        .verify_slice(&tag)
        .map_err(|_| Error::user("passkey verification refused"))?;
    Ok(expected)
}

pub fn create(
    paths: &Paths,
    name: &str,
    rp: &str,
    expected_origin: &str,
    pin_secret: &str,
) -> Result<Value, Error> {
    crate::name::parse_name(name)?;
    crate::name::parse_name(pin_secret)?;
    if name == pin_secret {
        return Err(Error::user(
            "passkey and verification secret must use different names",
        ));
    }
    let vault = Vault::open(paths)?;
    let _lock = lock(paths, name)?;
    match vault.info(name) {
        Ok(_) => {
            return Err(Error::user(
                "stored name already exists; passkeys are never overwritten",
            ))
        }
        Err(Error::NotFound(_)) => {}
        Err(error) => return Err(error),
    }
    let canonical_origin = origin(expected_origin, rp)?;
    let _pin = verify_pin(&vault, pin_secret)?;
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
        .map_err(|_| Error::user("could not generate passkey"))?;
    let der = private_key.to_pkcs8_der().map_err(|_| invalid())?;
    let mut credential_id = [0u8; 32];
    let mut prf_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut credential_id);
    OsRng.fill_bytes(prf_key.as_mut());
    let credential = Credential {
        version: 1,
        rp_id: rp.to_owned(),
        origin: canonical_origin,
        credential_id: encode(credential_id),
        user_handle: String::new(),
        private_key: encode(der.as_bytes()),
        prf_key: encode(prf_key.as_ref()),
        pin_secret: pin_secret.to_owned(),
        registered: false,
        counter: 0,
    };
    store(&vault, name, &credential)?;
    info(paths, name)
}

pub fn info(paths: &Paths, name: &str) -> Result<Value, Error> {
    let vault = Vault::open(paths)?;
    let credential = load(&vault, name)?;
    Ok(
        json!({"event":"passkey-info", "name":name,"rpId":credential.rp_id,
        "origin":credential.origin,"credentialId":credential.credential_id,
        "registered":credential.registered,"signCount":credential.counter,
        "algorithm":"RS256","prf":true,"provider":"hush-software-v1"}),
    )
}

// The broker's only output is metadata. Protocol responses, including PRF results,
// go to the authorized child's private stdin and never to the terminal.
pub fn run(paths: &Paths, name: &str, command: &[String]) -> Result<(), Error> {
    if command.is_empty() {
        return Err(Error::user("missing passkey worker command"));
    }
    let vault = Vault::open(paths)?;
    let _lock = lock(paths, name)?;
    let credential = load(&vault, name)?;
    let _pin = verify_pin(&vault, &credential.pin_secret)?;
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for key in [
        "BW_SESSION",
        "BW_CLIENTID",
        "BW_CLIENTSECRET",
        "BW_PASSWORD",
        "BITWARDENCLI_APPDATA_DIR",
        "HUSH_PASSKEY_PIN",
    ] {
        cmd.env_remove(key);
    }
    let mut child = cmd.spawn()?;
    let mut input = child.stdin.take().ok_or_else(invalid)?;
    let mut output = BufReader::new(child.stdout.take().ok_or_else(invalid)?);
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || loop {
        let mut line = Zeroizing::new(String::new());
        match output.by_ref().take(LIMIT + 1).read_line(&mut line) {
            Ok(0) => break,
            Ok(read) if read as u64 <= LIMIT && line.ends_with('\n') => {
                if sender.send(Ok(line)).is_err() {
                    break;
                }
            }
            _ => {
                let _ = sender.send(Err(Error::user("passkey worker exceeded protocol limits")));
                break;
            }
        }
    });
    let mut count = 0u32;
    let result = (|| -> Result<(), Error> {
        loop {
            let line = match receiver.recv_timeout(std::time::Duration::from_secs(300)) {
                Ok(result) => result?,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(_) => return Err(Error::user("passkey worker timed out")),
            };
            if count >= 1024 {
                return Err(Error::user("passkey worker exceeded protocol limits"));
            }
            let request: Value = serde_json::from_str(&line).map_err(|_| invalid())?;
            let mut response = match respond(&vault, name, &request) {
                Ok(value) => json!({"ok":true,"credential":value}),
                Err(_) => json!({"ok":false,"error":"NotAllowedError"}),
            };
            let raw = Zeroizing::new(serde_json::to_vec(&response)?);
            wipe(&mut response);
            input.write_all(&raw)?;
            input.write_all(b"\n")?;
            input.flush()?;
            count += 1;
        }
        Ok(())
    })();
    drop(input);
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    result?;
    if !status.success() {
        return Err(Error::user("passkey worker failed; raw output suppressed"));
    }
    println!(
        "{}",
        json!({"event":"passkey-session-completed","name":name,"requests":count})
    );
    Ok(())
}

fn prf(credential: &Credential, extension: &Value, create: bool) -> Result<Value, Error> {
    if extension.is_null() {
        return Ok(json!({}));
    }
    if !extension.is_object() || (create && extension.get("evalByCredential").is_some()) {
        return Err(invalid());
    }
    let mut values = extension.get("eval");
    if let Some(by_id) = extension.get("evalByCredential") {
        let by_id = by_id.as_object().ok_or_else(invalid)?;
        if let Some(selected) = by_id.get(&credential.credential_id) {
            values = Some(selected);
        }
    }
    let mut output = json!({});
    if create {
        output["enabled"] = json!(true);
    }
    if let Some(values) = values {
        let key = Zeroizing::new(decode(&credential.prf_key)?);
        let evaluate = |value: &str| -> Result<String, Error> {
            let salt = decode(value)?;
            let mut hash = Sha256::new();
            hash.update(b"WebAuthn PRF\0");
            hash.update(salt);
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).map_err(|_| invalid())?;
            mac.update(&hash.finalize());
            let result = Zeroizing::new(mac.finalize().into_bytes().to_vec());
            Ok(encode(&*result))
        };
        let mut results = json!({"first":evaluate(field(values,"first")?)?});
        if let Some(second) = values.get("second") {
            results["second"] = json!(evaluate(second.as_str().ok_or_else(invalid)?)?);
        }
        output["results"] = results;
    }
    Ok(json!({"prf":output}))
}

fn respond(vault: &Vault, name: &str, request: &Value) -> Result<Value, Error> {
    let mut credential = load(vault, name)?;
    let _pin = verify_pin(vault, &credential.pin_secret)?;
    let operation = field(request, "op")?;
    if field(request, "origin")? != credential.origin {
        return Err(invalid());
    }
    let options = request.get("publicKey").ok_or_else(invalid)?;
    let challenge = decode(field(options, "challenge")?)?;
    if challenge.len() < 16 || challenge.len() > 1024 {
        return Err(invalid());
    }
    let create = match operation {
        "create" => true,
        "get" => false,
        _ => return Err(invalid()),
    };
    let rp = if create {
        field(&options["rp"], "id")?
    } else {
        field(options, "rpId")?
    };
    if rp != credential.rp_id || options.get("remoteDesktopClientOverride").is_some() {
        return Err(invalid());
    }
    let allowed = options.get("allowCredentials").and_then(Value::as_array);
    if let Some(allowed) = allowed {
        if !allowed.is_empty()
            && !allowed
                .iter()
                .any(|item| item["type"] == "public-key" && item["id"] == credential.credential_id)
        {
            return Err(invalid());
        }
    }
    if let Some(by_id) = options["extensions"]["prf"].get("evalByCredential") {
        let allowed = allowed
            .filter(|items| !items.is_empty())
            .ok_or_else(invalid)?;
        for id in by_id.as_object().ok_or_else(invalid)?.keys() {
            decode(id)?;
            if id.is_empty() || !allowed.iter().any(|item| item["id"] == *id) {
                return Err(invalid());
            }
        }
    }
    let extension_results = prf(&credential, &options["extensions"]["prf"], create)?;
    let raw_key = Zeroizing::new(decode(&credential.private_key)?);
    let key = RsaPrivateKey::from_pkcs8_der(&raw_key).map_err(|_| invalid())?;
    let public = RsaPublicKey::from(&key);
    let client_data = serde_json::to_vec(
        &json!({"type":if create {"webauthn.create"} else {"webauthn.get"},
        "challenge":encode(challenge),"origin":credential.origin,"crossOrigin":false}),
    )?;
    let mut auth = Sha256::digest(credential.rp_id.as_bytes()).to_vec();
    let mut result = json!({"id":credential.credential_id,"rawId":credential.credential_id,"type":"public-key",
        "authenticatorAttachment":"platform","clientExtensionResults":extension_results});
    if create {
        if credential.registered {
            return Err(Error::user("passkey is already registered"));
        }
        if !options["pubKeyCredParams"]
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .any(|item| item["type"] == "public-key" && item["alg"] == -257)
        {
            return Err(invalid());
        }
        if options["excludeCredentials"]
            .as_array()
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["id"] == credential.credential_id)
            })
        {
            return Err(invalid());
        }
        if options["authenticatorSelection"]["authenticatorAttachment"] == "cross-platform" {
            return Err(invalid());
        }
        let handle = decode(field(&options["user"], "id")?)?;
        if handle.is_empty() || handle.len() > 64 {
            return Err(invalid());
        }
        credential.user_handle = encode(handle);
        credential.registered = true;
        auth.push(0x45); // UP + UV + attested credential data; agent-authorized software session.
        auth.extend_from_slice(&0u32.to_be_bytes());
        auth.extend_from_slice(&[0u8; 16]);
        let id = decode(&credential.credential_id)?;
        auth.extend_from_slice(&(id.len() as u16).to_be_bytes());
        auth.extend(id);
        // COSE RSA key: kty=RSA, alg=RS256, modulus, exponent.
        auth.extend_from_slice(&[0xa4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20]);
        cbor_bytes(&mut auth, &public.n().to_bytes_be());
        auth.push(0x21);
        cbor_bytes(&mut auth, &public.e().to_bytes_be());
        let mut attestation = vec![
            0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e', 0x67,
        ];
        attestation.extend_from_slice(b"attStmt");
        attestation.extend_from_slice(&[0xa0, 0x68]);
        attestation.extend_from_slice(b"authData");
        cbor_bytes(&mut attestation, &auth);
        let spki = public.to_public_key_der().map_err(|_| invalid())?;
        result["response"] = json!({"clientDataJSON":encode(client_data),"attestationObject":encode(attestation),
            "authenticatorData":encode(auth),"publicKey":encode(spki.as_bytes()),"publicKeyAlgorithm":-257,"transports":["internal"]});
    } else {
        if !credential.registered {
            return Err(Error::user("passkey has not been registered"));
        }
        credential.counter = credential.counter.checked_add(1).ok_or_else(invalid)?;
        auth.push(0x05);
        auth.extend_from_slice(&credential.counter.to_be_bytes());
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        let signature =
            rsa::pkcs1v15::SigningKey::<Sha256>::new(key).sign_with_rng(&mut OsRng, &message);
        result["response"] = json!({"clientDataJSON":encode(client_data),"authenticatorData":encode(auth),
            "signature":encode(signature.to_vec()),"userHandle":credential.user_handle});
    }
    store(vault, name, &credential)?;
    Ok(result)
}
fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    match bytes.len() {
        0..=23 => out.push(0x40 | bytes.len() as u8),
        24..=255 => out.extend_from_slice(&[0x58, bytes.len() as u8]),
        _ => {
            out.push(0x59);
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        }
    }
    out.extend_from_slice(bytes);
}

pub fn list(paths: &Paths) -> Result<Value, Error> {
    let vault = Vault::open(paths)?;
    let mut values = Vec::new();
    for item in vault.list()? {
        if item.source == "passkey" {
            values.push(info(paths, &item.name)?);
        }
    }
    Ok(json!({"event":"passkey-list","passkeys":values}))
}
pub fn remove(paths: &Paths, name: &str) -> Result<Value, Error> {
    let vault = Vault::open(paths)?;
    let _lock = lock(paths, name)?;
    load(&vault, name)?;
    vault.remove(name)?;
    Ok(json!({"event":"passkey-removed","name":name}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prf_matches_independently_computed_domain_separated_hmac_vector() {
        let value = Credential {
            version: 1,
            rp_id: "example.test".to_owned(),
            origin: "https://example.test".to_owned(),
            credential_id: "AQID".to_owned(),
            user_handle: "BAUG".to_owned(),
            private_key: String::new(),
            prf_key: encode([17u8; 32]),
            pin_secret: "pin".to_owned(),
            registered: true,
            counter: 0,
        };
        let output = prf(&value, &json!({"eval":{"first":"AQID"}}), false).unwrap();
        assert!(output["prf"]["results"]["first"] == "3V8pfHUyL_vQFCKsDJD7aopn3KXaUAHxikAU16WQlxw");
        assert!(prf(&value, &json!({"evalByCredential":{}}), true).is_err());
    }
}
