use serde::{Deserialize, Serialize};

use crate::paths::{atomic_write, Paths};
use crate::Error;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub signal: SignalConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalConfig {
    #[serde(default)]
    pub account: Option<String>,
    #[serde(default = "default_device_name")]
    pub device_name: String,
    #[serde(default = "default_allow_from")]
    pub allow_from: Vec<String>,
    #[serde(default)]
    pub socket: Option<String>,
}

fn default_device_name() -> String {
    "hush".into()
}

fn default_allow_from() -> Vec<String> {
    vec!["self".into()]
}

impl Default for SignalConfig {
    fn default() -> Self {
        Self {
            account: None,
            device_name: default_device_name(),
            allow_from: default_allow_from(),
            socket: None,
        }
    }
}

impl Config {
    pub fn load(paths: &Paths) -> Result<Self, Error> {
        let file = paths.config_file();
        if !file.exists() {
            return Err(Error::NotInitialized);
        }
        let raw = std::fs::read_to_string(file)?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save(&self, paths: &Paths) -> Result<(), Error> {
        paths.ensure_layout()?;
        let raw = serde_json::to_vec_pretty(self)?;
        atomic_write(&paths.config_file(), &raw)
    }

    pub fn allow(&mut self, id: &str) {
        let id = id.trim();
        if id.is_empty() {
            return;
        }
        if !self
            .signal
            .allow_from
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(id))
        {
            self.signal.allow_from.push(id.to_string());
        }
    }
}
