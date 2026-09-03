use serde::{Deserialize, Serialize};

use crate::paths::{atomic_write, Paths};
use crate::Error;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub bitwarden: BitwardenConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BitwardenConfig {
    /// Trash vault items after they are ingested (`--consume` overrides per run).
    #[serde(default)]
    pub consume_after_pull: bool,
}

impl Config {
    pub fn load(paths: &Paths) -> Result<Self, Error> {
        let file = paths.config_file();
        if !file.exists() {
            return Err(Error::NotInitialized);
        }
        let raw = std::fs::read_to_string(file)?;
        // Tolerate configs written by older hush releases.
        let value: serde_json::Value = serde_json::from_str(&raw)?;
        if value.get("bitwarden").is_some() || value.get("signal").is_none() {
            Ok(serde_json::from_value(value)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, paths: &Paths) -> Result<(), Error> {
        paths.ensure_layout()?;
        let raw = serde_json::to_vec_pretty(self)?;
        atomic_write(&paths.config_file(), &raw)
    }
}
