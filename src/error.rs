use std::io;
use std::process::ExitStatus;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not initialized; run `hush init`")]
    NotInitialized,
    #[error("already initialized")]
    AlreadyInitialized,
    #[error("Bitwarden vault is locked or not logged in; run `bw login` then `bw unlock` and export BW_SESSION")]
    NotLoggedIn,
    #[error("bw not found (install the Bitwarden CLI or set HUSH_BW_BIN)")]
    BwMissing,
    #[error("secret `{0}` not found")]
    NotFound(String),
    #[error("invalid name: {0}")]
    InvalidName(String),
    #[error("invalid env var name: {0}")]
    InvalidEnv(String),
    #[error("{0}")]
    User(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("encrypt: {0}")]
    Encrypt(String),
    #[error("decrypt: {0}")]
    Decrypt(String),
    #[error("command `{0}` failed with {1}")]
    CommandFailed(String, ExitStatus),
}

impl Error {
    pub fn user(msg: impl Into<String>) -> Self {
        Self::User(msg.into())
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NotFound(_) => 2,
            Self::NotLoggedIn | Self::NotInitialized => 3,
            Self::BwMissing => 4,
            Self::CommandFailed(_, status) => status.code().unwrap_or(1),
            _ => 1,
        }
    }
}
