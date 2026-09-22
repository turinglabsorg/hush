//! Public keys for hush box. Ciphertext does not come here.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::VerifyingKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::Mutex;

pub const SIGNED_PREFIX: &str = "hush-box-v1";

#[derive(Clone)]
pub struct AppState {
    store: Store,
}

#[derive(Clone)]
pub enum Store {
    Memory(MemoryStore),
    Firestore(FirestoreStore),
}

impl Store {
    async fn get(&self, name: &str) -> Result<Option<String>, DirectoryError> {
        match self {
            Self::Memory(store) => store.get(name).await,
            Self::Firestore(store) => store.get(name).await,
        }
    }

    async fn put(&self, name: &str, pem: String) -> Result<(), DirectoryError> {
        match self {
            Self::Memory(store) => store.put(name, pem).await,
            Self::Firestore(store) => store.put(name, pem).await,
        }
    }

    async fn insert_box(&self, id: String, to: String, uses: u32, file: Option<String>, envelope: serde_json::Value) -> Result<(), DirectoryError> {
        match self {
            Self::Memory(store) => store.insert_box(id, SealedBox { to, uses, file, envelope }).await,
            Self::Firestore(store) => store.insert_box(&id, &to, uses, file.as_deref(), &envelope).await,
        }
    }

    async fn pull_box(&self, id: &str) -> Result<Option<(serde_json::Value, u32)>, DirectoryError> {
        match self {
            Self::Memory(store) => Ok(store.pull_box(id).await?.map(|(envelope, left, _)| (envelope, left))),
            Self::Firestore(store) => store.pull_box(id).await,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error("{0}")]
    Bad(String),
    #[error("{0}")]
    Upstream(String),
}

#[derive(Clone, Default)]
struct SealedBox {
    to: String,
    uses: u32,
    #[allow(dead_code)]
    file: Option<String>,
    envelope: serde_json::Value,
}

#[derive(Clone, Default)]
pub struct MemoryStore {
    keys: Arc<Mutex<HashMap<String, String>>>,
    boxes: Arc<Mutex<HashMap<String, SealedBox>>>,
}

impl MemoryStore {
    async fn get(&self, name: &str) -> Result<Option<String>, DirectoryError> {
        Ok(self.keys.lock().await.get(name).cloned())
    }

    async fn put(&self, name: &str, pem: String) -> Result<(), DirectoryError> {
        self.keys.lock().await.insert(name.to_string(), pem);
        Ok(())
    }

    async fn insert_box(&self, id: String, record: SealedBox) -> Result<(), DirectoryError> {
        self.boxes.lock().await.insert(id, record);
        Ok(())
    }

    async fn pull_box(&self, id: &str) -> Result<Option<(serde_json::Value, u32, String)>, DirectoryError> {
        let mut boxes = self.boxes.lock().await;
        let Some(record) = boxes.get_mut(id) else {
            return Ok(None);
        };
        if record.uses == 0 {
            boxes.remove(id);
            return Ok(None);
        }
        record.uses -= 1;
        let left = record.uses;
        let envelope = record.envelope.clone();
        let to = record.to.clone();
        if left == 0 {
            boxes.remove(id);
        }
        Ok(Some((envelope, left, to)))
    }
}

#[derive(Clone)]
pub struct FirestoreStore {
    project: String,
    database: String,
    client: reqwest::Client,
}

impl FirestoreStore {
    pub fn new(project: String) -> Self {
        let database = std::env::var("FIRESTORE_DATABASE").unwrap_or_else(|_| "(default)".into());
        Self {
            project,
            database,
            client: reqwest::Client::new(),
        }
    }

    fn document_url(&self, name: &str) -> String {
        let database = self.database.replace('(', "%28").replace(')', "%29");
        format!(
            "https://firestore.googleapis.com/v1/projects/{}/databases/{}/documents/hush_keys/{}",
            self.project, database, name
        )
    }

    async fn token(&self) -> Result<String, DirectoryError> {
        if let Ok(token) = std::env::var("GOOGLE_ACCESS_TOKEN") {
            if !token.is_empty() {
                return Ok(token);
            }
        }
        let response = self
            .client
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|err| DirectoryError::Upstream(err.to_string()))?;
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|err| DirectoryError::Upstream(err.to_string()))?;
        body.get("access_token")
            .and_then(|value| value.as_str())
            .map(str::to_string)
            .ok_or_else(|| {
                DirectoryError::Upstream("metadata server returned no access token".into())
            })
    }
}

impl FirestoreStore {
    async fn get(&self, name: &str) -> Result<Option<String>, DirectoryError> {
        let token = self.token().await?;
        let response = self
            .client
            .get(self.document_url(name))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| DirectoryError::Upstream(err.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(DirectoryError::Upstream(format!(
                "firestore get {}",
                response.status()
            )));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|err| DirectoryError::Upstream(err.to_string()))?;
        Ok(pem_from_document(&body))
    }

    async fn put(&self, name: &str, pem: String) -> Result<(), DirectoryError> {
        let token = self.token().await?;
        let url = format!(
            "{}?updateMask.fieldPaths=publicKeyPem&updateMask.fieldPaths=updatedAt",
            self.document_url(name)
        );
        let response = self
            .client
            .patch(url)
            .bearer_auth(token)
            .json(&document_body(&pem))
            .send()
            .await
            .map_err(|err| DirectoryError::Upstream(err.to_string()))?;
        if !response.status().is_success() {
            return Err(DirectoryError::Upstream(format!(
                "firestore put {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn insert_box(
        &self,
        id: &str,
        to: &str,
        uses: u32,
        file: Option<&str>,
        envelope: &serde_json::Value,
    ) -> Result<(), DirectoryError> {
        let encoded = envelope.to_string();
        if encoded.len() > 900_000 {
            return Err(DirectoryError::Bad(
                "sealed box is over 900KB; Firestore documents cannot hold it".into(),
            ));
        }
        let token = self.token().await?;
        let url = format!(
            "{}?updateMask.fieldPaths=to&updateMask.fieldPaths=uses&updateMask.fieldPaths=file&updateMask.fieldPaths=envelope",
            self.box_url(id)
        );
        let response = self
            .client
            .patch(url)
            .bearer_auth(token)
            .json(&serde_json::json!({
                "fields": {
                    "to": { "stringValue": to },
                    "uses": { "integerValue": uses.to_string() },
                    "file": { "stringValue": file.unwrap_or("") },
                    "envelope": { "stringValue": encoded }
                }
            }))
            .send()
            .await
            .map_err(|err| DirectoryError::Upstream(err.to_string()))?;
        if !response.status().is_success() {
            return Err(DirectoryError::Upstream(format!(
                "firestore box {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn pull_box(&self, id: &str) -> Result<Option<(serde_json::Value, u32)>, DirectoryError> {
        let token = self.token().await?;
        let response = self
            .client
            .get(self.box_url(id))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|err| DirectoryError::Upstream(err.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(DirectoryError::Upstream(format!(
                "firestore box {}",
                response.status()
            )));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|err| DirectoryError::Upstream(err.to_string()))?;
        let uses: u32 = body
            .pointer("/fields/uses/integerValue")
            .and_then(|value| value.as_str())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let envelope = body
            .pointer("/fields/envelope/stringValue")
            .and_then(|value| value.as_str())
            .and_then(|value| serde_json::from_str(value).ok())
            .ok_or_else(|| DirectoryError::Upstream("firestore box has no envelope".into()))?;
        if uses == 0 {
            let _ = self.client.delete(self.box_url(id)).bearer_auth(&token).send().await;
            return Ok(None);
        }
        let left = uses - 1;
        if left == 0 {
            let _ = self.client.delete(self.box_url(id)).bearer_auth(token).send().await;
        } else {
            let _ = self
                .client
                .patch(format!(
                    "{}?updateMask.fieldPaths=uses",
                    self.box_url(id)
                ))
                .bearer_auth(token)
                .json(&serde_json::json!({
                    "fields": { "uses": { "integerValue": left.to_string() } }
                }))
                .send()
                .await;
        }
        Ok(Some((envelope, left)))
    }

    fn box_url(&self, id: &str) -> String {
        let database = self.database.replace('(', "%28").replace(')', "%29");
        format!(
            "https://firestore.googleapis.com/v1/projects/{}/databases/{}/documents/hush_boxes/{id}",
            self.project, database
        )
    }
}

pub fn document_body(pem: &str) -> serde_json::Value {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    serde_json::json!({
        "fields": {
            "publicKeyPem": { "stringValue": pem },
            "updatedAt": { "timestampValue": now }
        }
    })
}

pub fn pem_from_document(value: &serde_json::Value) -> Option<String> {
    value
        .pointer("/fields/publicKeyPem/stringValue")
        .and_then(|item| item.as_str())
        .map(str::to_string)
}

pub fn signed_message(name: &str, public_key_pem: &str) -> Vec<u8> {
    format!("{SIGNED_PREFIX}\n{name}\n{public_key_pem}").into_bytes()
}

fn valid_name(name: &str) -> bool {
    let Some(local) = name.strip_suffix("@hush.sh") else {
        return false;
    };
    let mut chars = local.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && local.len() <= 64
        && !local.contains("..")
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn verify(pem: &str, message: &[u8], signature_b64: &str) -> Result<(), DirectoryError> {
    let key = RsaPublicKey::from_public_key_pem(pem.trim())
        .map_err(|err| DirectoryError::Bad(err.to_string()))?;
    let bytes = STANDARD
        .decode(signature_b64.trim())
        .map_err(|err| DirectoryError::Bad(err.to_string()))?;
    let signature = rsa::pss::Signature::try_from(bytes.as_slice())
        .map_err(|err| DirectoryError::Bad(err.to_string()))?;
    VerifyingKey::<Sha256>::new(key)
        .verify(message, &signature)
        .map_err(|_| DirectoryError::Bad("signature rejected".into()))
}

#[derive(Deserialize)]
struct PutKey {
    public_key_pem: String,
    signature_b64: String,
}

#[derive(Serialize)]
struct GetKey {
    name: String,
    public_key_pem: String,
}

pub fn router(store: Store) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/keys/:name", get(read_key).put(write_key))
        .route("/v1/boxes", axum::routing::post(create_box))
        .route("/v1/boxes/:id/pull", axum::routing::post(pull_box))
        .with_state(AppState { store })
}

async fn read_key(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<GetKey>, StatusCode> {
    if !valid_name(&name) {
        return Err(StatusCode::BAD_REQUEST);
    }
    match state.store.get(&name).await {
        Ok(Some(pem)) => Ok(Json(GetKey {
            name,
            public_key_pem: pem,
        })),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::BAD_GATEWAY),
    }
}

async fn write_key(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<PutKey>,
) -> Result<StatusCode, StatusCode> {
    if !valid_name(&name) || body.public_key_pem.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let message = signed_message(&name, &body.public_key_pem);
    let existing = state
        .store
        .get(&name)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let verifier = existing.as_deref().unwrap_or(body.public_key_pem.as_str());
    verify(verifier, &message, &body.signature_b64).map_err(|_| StatusCode::UNAUTHORIZED)?;
    state
        .store
        .put(&name, body.public_key_pem)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct CreateBox {
    to: String,
    uses: u32,
    file: Option<String>,
    envelope: serde_json::Value,
}

async fn create_box(
    State(state): State<AppState>,
    Json(body): Json<CreateBox>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !valid_name(&body.to) || body.uses == 0 || body.envelope.is_null() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let id = new_id();
    state
        .store
        .insert_box(id.clone(), body.to, body.uses, body.file, body.envelope)
        .await
        .map_err(|err| match err {
            DirectoryError::Bad(_) => StatusCode::PAYLOAD_TOO_LARGE,
            DirectoryError::Upstream(_) => StatusCode::BAD_GATEWAY,
        })?;
    Ok(Json(serde_json::json!({ "id": id })))
}

async fn pull_box(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if id.len() < 16 || !id.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    match state.store.pull_box(&id).await {
        Ok(Some((envelope, uses_left))) => Ok(Json(serde_json::json!({
            "envelope": envelope,
            "uses_left": uses_left,
        }))),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::BAD_GATEWAY),
    }
}

fn new_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn memory_router() -> Router {
    router(Store::Memory(MemoryStore::default()))
}

pub fn serve_store() -> Store {
    match std::env::var("FIRESTORE_PROJECT") {
        Ok(project) if !project.is_empty() => Store::Firestore(FirestoreStore::new(project)),
        _ => Store::Memory(MemoryStore::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use rand::rngs::OsRng;
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use rsa::pss::BlindedSigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::RsaPrivateKey;
    use tower::ServiceExt;

    fn signed(name: &str, private: &RsaPrivateKey, pem: &str) -> String {
        let signer = BlindedSigningKey::<Sha256>::new(private.clone());
        let sig = signer.sign_with_rng(&mut OsRng, &signed_message(name, pem));
        STANDARD.encode(sig.to_bytes())
    }

    async fn body_string(body: Body) -> String {
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn publish_and_fetch_roundtrip() {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem = rsa::RsaPublicKey::from(&private)
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let app = memory_router();
        let put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/keys/alice%40hush.sh")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "public_key_pem": pem,
                            "signature_b64": signed("alice@hush.sh", &private, &pem),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put.status(), StatusCode::NO_CONTENT);

        let get = app
            .oneshot(
                Request::builder()
                    .uri("/v1/keys/alice%40hush.sh")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        let raw = body_string(get.into_body()).await;
        assert!(raw.contains("BEGIN PUBLIC KEY"));
        assert!(!raw.contains("PRIVATE"));
    }

    #[tokio::test]
    async fn replace_requires_the_current_key() {
        let mut rng = OsRng;
        let first = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let first_pem = rsa::RsaPublicKey::from(&first)
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let second = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let second_pem = rsa::RsaPublicKey::from(&second)
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let app = memory_router();
        let ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/keys/alice%40hush.sh")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "public_key_pem": first_pem,
                            "signature_b64": signed("alice@hush.sh", &first, &first_pem),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::NO_CONTENT);

        let rejected = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/keys/alice%40hush.sh")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "public_key_pem": second_pem,
                            "signature_b64": signed("alice@hush.sh", &second, &second_pem),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn firestore_document_keeps_only_the_public_key() {
        let body = document_body("-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n");
        let pem = pem_from_document(&body).unwrap();
        assert!(pem.contains("BEGIN PUBLIC KEY"));
        assert!(!body.to_string().contains("PRIVATE"));
    }
}
