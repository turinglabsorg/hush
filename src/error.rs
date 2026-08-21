use std::io;
use std::process::ExitStatus;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not initialized; run `hush init`")]
    NotInitialized,
    #[error("already initialized")]
    AlreadyInitialized,
    #[error("Signal is not linked; run `hush signal link`")]
    NotLinked,
    #[error("signal-cli not found (install it or set HUSH_SIGNAL_CLI)")]
    SignalCliMissing,
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
            Self::NotLinked | Self::NotInitialized => 3,
            Self::SignalCliMissing => 4,
            Self::CommandFailed(_, status) => status.code().unwrap_or(1),
            _ => 1,
        }
    }
}
