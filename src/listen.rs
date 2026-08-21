use serde::Serialize;
use serde_json::Value;

use crate::config::Config;
use crate::paths::Paths;
use crate::protocol::{parse_body, Ingest};
use crate::signal::{incoming_from_rpc, Incoming};
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
        notify: bool,
    },
    Ignored {
        reason: String,
    },
}

pub fn listen(paths: &Paths, json: bool) -> Result<(), Error> {
    let config = Config::load(paths)?;
    let account = config.signal.account.clone().ok_or(Error::NotLinked)?;
    let vault = Vault::open(paths)?;
    let mut rpc = crate::signal::open_rpc(&config)?;
    if !json {
        eprintln!(
            "hush listen: waiting for Signal messages (`hush put NAME` then the secret on the next lines)"
        );
        eprintln!(
            "hush listen: account {account}, allow_from {:?}",
            config.signal.allow_from
        );
    }
    while let Some(line) = rpc.read_line()? {
        match handle_line(&line, &vault, &config) {
            Ok(Some(event)) => {
                emit(&event, json);
                if let Some(ack) = ack_message(&event) {
                    if let Some(incoming) = parse_incoming_silent(&line) {
                        if let Some(recipient) =
                            incoming.ack_recipient(config.signal.account.as_deref())
                        {
                            let _ = rpc.send_text(&recipient, &ack);
                        }
                    }
                }
            }
            Ok(None) => {}
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
    }
    Ok(())
}

pub fn handle_line(
    line: &str,
    vault: &Vault,
    config: &Config,
) -> Result<Option<ListenEvent>, Error> {
    let line = line.trim();
    if line.is_empty() || !line.starts_with('{') {
        return Ok(None);
    }
    let value: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let Some(incoming) = incoming_from_rpc(&value) else {
        return Ok(None);
    };
    Ok(Some(ingest(vault, config, &incoming)?))
}

fn parse_incoming_silent(line: &str) -> Option<Incoming> {
    let value: Value = serde_json::from_str(line.trim()).ok()?;
    incoming_from_rpc(&value)
}

pub fn ingest(vault: &Vault, config: &Config, incoming: &Incoming) -> Result<ListenEvent, Error> {
    if incoming.is_group {
        return Ok(ListenEvent::Ignored {
            reason: "group messages are ignored".into(),
        });
    }
    if !incoming.allowed(&config.signal.allow_from, config.signal.account.as_deref()) {
        return Ok(ListenEvent::Rejected {
            reason: format!(
                "sender {} is not in allow_from",
                incoming.sender_label(config.signal.account.as_deref())
            ),
            notify: false,
        });
    }
    match parse_body(&incoming.body) {
        Ingest::NotForUs => Ok(ListenEvent::Ignored {
            reason: "not a hush put message".into(),
        }),
        Ingest::Error(reason) => Ok(ListenEvent::Rejected {
            reason,
            notify: true,
        }),
        Ingest::Put { name, value } => {
            let replaced = vault.info(&name).is_ok();
            let sender = incoming.sender_label(config.signal.account.as_deref());
            vault.put(&name, &value, "signal", &sender)?;
            Ok(ListenEvent::Stored {
                name,
                sender,
                replaced,
            })
        }
    }
}

fn ack_message(event: &ListenEvent) -> Option<String> {
    match event {
        ListenEvent::Stored { name, .. } => Some(format!("hush: stored {name}")),
        ListenEvent::Rejected {
            reason,
            notify: true,
        } => Some(format!("hush: {reason}")),
        _ => None,
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
        ListenEvent::Rejected { reason, .. } => println!("rejected: {reason}"),
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
    use crate::paths::Paths;
    use crate::vault::Vault;
    use tempfile::TempDir;

    fn setup() -> (TempDir, Paths, Vault, Config) {
        let dir = TempDir::new().unwrap();
        let paths = Paths::new(dir.path().join("hush"));
        Vault::init(&paths).unwrap();
        let mut config = Config::default();
        config.signal.account = Some("+15551234567".into());
        config.save(&paths).unwrap();
        let vault = Vault::open(&paths).unwrap();
        (dir, paths, vault, config)
    }

    #[test]
    fn stores_note_to_self_and_never_echoes_secret() {
        let (_dir, paths, vault, config) = setup();
        let line = r#"{"jsonrpc":"2.0","method":"receive","params":{"envelope":{"sourceNumber":"+15551234567","syncMessage":{"sentMessage":{"message":"hush put stripe-prod\nsk-live-VERY-SECRET"}}}}}"#;
        let event = handle_line(line, &vault, &config).unwrap().unwrap();
        match event {
            ListenEvent::Stored { name, sender, .. } => {
                assert_eq!(name, "stripe-prod");
                assert_eq!(sender, "self");
            }
            other => panic!("{other:?}"),
        }
        let dumped = serde_json::to_string(&handle_line(line, &vault, &config).unwrap()).unwrap();
        assert!(!dumped.contains("VERY-SECRET"));
        assert_eq!(
            &vault.get("stripe-prod").unwrap()[..],
            b"sk-live-VERY-SECRET"
        );
        let ciphertext = std::fs::read(paths.secret_file("stripe-prod")).unwrap();
        assert!(!String::from_utf8_lossy(&ciphertext).contains("VERY-SECRET"));
    }

    #[test]
    fn rejects_strangers() {
        let (_dir, _paths, vault, config) = setup();
        let line = r#"{"jsonrpc":"2.0","method":"receive","params":{"envelope":{"sourceNumber":"+1999","dataMessage":{"message":"hush put x\nsecret"}}}}"#;
        let event = handle_line(line, &vault, &config).unwrap().unwrap();
        assert!(matches!(event, ListenEvent::Rejected { notify: false, .. }));
        assert!(vault.get("x").is_err());
    }
}
