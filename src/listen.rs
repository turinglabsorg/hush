use std::time::Duration;

use serde::Serialize;

use crate::bitwarden;
use crate::config::Config;
use crate::paths::Paths;
use crate::vault::Vault;
use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ListenEvent {
    Stored {
        name: String,
        sender: String,
        replaced: bool,
    },
    Rejected {
        reason: String,
    },
    Ignored {
        reason: String,
    },
}

/// One poll of the agent's Bitwarden vault for `hush put NAME` items.
pub fn poll_once(vault: &Vault, consume: bool) -> Result<Vec<ListenEvent>, Error> {
    bitwarden::sync()?;
    let items = bitwarden::list_items(Some("hush put"))?;
    let mut events = Vec::new();
    for item in &items {
        match crate::pull::ingest_item(vault, item)? {
            ListenEvent::Ignored { .. } => {}
            event => {
                if consume {
                    if let ListenEvent::Stored { .. } = &event {
                        bitwarden::delete_item(&item.id)?;
                    }
                }
                events.push(event);
            }
        }
    }
    Ok(events)
}

pub fn listen(paths: &Paths, json: bool, interval_secs: u64, consume: bool) -> Result<(), Error> {
    let config = Config::load(paths)?;
    let vault = Vault::open(paths)?;
    let consume = consume || config.bitwarden.consume_after_pull;
    let interval = Duration::from_secs(interval_secs.max(5));
    if !json {
        eprintln!(
            "hush listen: polling the Bitwarden vault every {}s for items named `hush put NAME`",
            interval.as_secs()
        );
    }
    loop {
        match poll_once(&vault, consume) {
            Ok(events) => {
                for event in &events {
                    emit(event, json);
                }
            }
            Err(err) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"event":"error","error": err.to_string()})
                    );
                } else {
                    eprintln!("hush listen: {err}");
                }
            }
        }
        std::thread::sleep(interval);
    }
}

pub(crate) fn emit(event: &ListenEvent, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string(event).unwrap_or_else(|_| "{}".into())
        );
        return;
    }
    match event {
        ListenEvent::Stored {
            name,
            sender,
            replaced,
        } => {
            if *replaced {
                println!("stored {name} (replaced) from {sender}");
            } else {
                println!("stored {name} from {sender}");
            }
        }
        ListenEvent::Rejected { reason } => println!("rejected: {reason}"),
        ListenEvent::Ignored { reason } => {
            if std::env::var_os("HUSH_VERBOSE").is_some() {
                eprintln!("ignored: {reason}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitwarden::{ItemLogin, VaultItem};
    use tempfile::TempDir;

    fn setup() -> (TempDir, Vault) {
        let dir = TempDir::new().unwrap();
        let paths = Paths::new(dir.path().join("hush"));
        Vault::init(&paths).unwrap();
        let vault = Vault::open(&paths).unwrap();
        (dir, vault)
    }

    #[test]
    fn stores_command_item_and_never_echoes_secret() {
        let (_dir, vault) = setup();
        let item = VaultItem {
            id: "1".into(),
            name: "hush put stripe-prod".into(),
            login: None,
            notes: Some("sk-live-VERY-SECRET".into()),
        };
        let event = crate::pull::ingest_item(&vault, &item).unwrap();
        match &event {
            ListenEvent::Stored { name, sender, .. } => {
                assert_eq!(name, "stripe-prod");
                assert_eq!(sender, "self");
            }
            other => panic!("{other:?}"),
        }
        let dumped = serde_json::to_string(&event).unwrap();
        assert!(!dumped.contains("VERY-SECRET"));
        assert_eq!(
            &vault.get("stripe-prod").unwrap()[..],
            b"sk-live-VERY-SECRET"
        );
    }

    #[test]
    fn rejects_malformed_command_item() {
        let (_dir, vault) = setup();
        let item = VaultItem {
            id: "1".into(),
            name: "hush put ../x".into(),
            login: Some(ItemLogin {
                password: Some("secret".into()),
            }),
            notes: None,
        };
        let event = crate::pull::ingest_item(&vault, &item).unwrap();
        assert!(matches!(event, ListenEvent::Rejected { .. }));
        assert!(vault.get("../x").is_err());
    }

    #[test]
    fn event_json_has_no_secret() {
        use serde_json::Value;

        let event = ListenEvent::Stored {
            name: "x".into(),
            sender: "self".into(),
            replaced: false,
        };
        let value: Value = serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(value["event"], "stored");
        assert_eq!(value["name"], "x");
    }
}
