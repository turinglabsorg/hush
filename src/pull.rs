use std::fmt;

use crate::config::Config;
use crate::listen::{emit, ingest, ListenEvent};
use crate::name::parse_name;
use crate::paths::Paths;
use crate::protocol::{is_hush_ack, parse_body, value_from_body, Ingest};
use crate::signal::{incoming_list_from_stdout, Incoming};
use crate::vault::Vault;
use crate::Error;

pub struct StoreOp {
    pub name: String,
    pub value: Vec<u8>,
    pub sender: String,
}

impl fmt::Debug for StoreOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreOp")
            .field("name", &self.name)
            .field("bytes", &self.value.len())
            .field("sender", &self.sender)
            .finish()
    }
}

pub fn pull(paths: &Paths, name: Option<&str>, json: bool, timeout_secs: u64) -> Result<(), Error> {
    let config = Config::load(paths)?;
    let account = config.signal.account.clone().ok_or(Error::NotLinked)?;
    let vault = Vault::open(paths)?;
    let stdout = crate::signal::receive_once(&account, timeout_secs)?;
    let incoming = incoming_list_from_stdout(&stdout);
    let ops = select_stores(&incoming, &config, name)?;
    if ops.is_empty() {
        return Err(match name {
            Some(name) => Error::user(format!("no Signal message found to store as `{name}`")),
            None => {
                Error::user("no hush put messages waiting; pass --name if you sent a raw secret")
            }
        });
    }

    let mut stored = Vec::new();
    for op in ops {
        let event = persist(&vault, &op)?;
        emit(&event, json);
        stored.push(op.name);
    }

    if let Some(last) = stored.last() {
        let recipient = account.clone();
        let _ = crate::signal::send_ack(&account, &recipient, last);
    }
    Ok(())
}

fn persist(vault: &Vault, op: &StoreOp) -> Result<ListenEvent, Error> {
    let replaced = vault.info(&op.name).is_ok();
    vault.put(&op.name, &op.value, "signal", &op.sender)?;
    Ok(ListenEvent::Stored {
        name: op.name.clone(),
        sender: op.sender.clone(),
        replaced,
    })
}

pub fn select_stores(
    incoming: &[Incoming],
    config: &Config,
    force_name: Option<&str>,
) -> Result<Vec<StoreOp>, Error> {
    let force_name = match force_name {
        Some(name) => Some(parse_name(name)?),
        None => None,
    };
    let eligible: Vec<&Incoming> = incoming
        .iter()
        .filter(|msg| !msg.is_group)
        .filter(|msg| msg.allowed(&config.signal.allow_from, config.signal.account.as_deref()))
        .filter(|msg| !is_hush_ack(&msg.body))
        .collect();

    if let Some(name) = force_name {
        let Some(msg) = eligible.last() else {
            return Ok(Vec::new());
        };
        let sender = msg.sender_label(config.signal.account.as_deref());
        let value = match parse_body(&msg.body) {
            Ingest::Put { value, .. } => value,
            Ingest::NotForUs => value_from_body(&msg.body).map_err(Error::user)?,
            Ingest::Error(reason) => return Err(Error::user(reason)),
        };
        return Ok(vec![StoreOp {
            name,
            value,
            sender,
        }]);
    }

    let mut ops = Vec::new();
    for msg in eligible {
        if let Ingest::Put { name, value } = parse_body(&msg.body) {
            ops.push(StoreOp {
                name,
                value,
                sender: msg.sender_label(config.signal.account.as_deref()),
            });
        }
    }
    Ok(ops)
}

pub fn pull_from_incoming(
    vault: &Vault,
    config: &Config,
    incoming: &[Incoming],
    force_name: Option<&str>,
) -> Result<Vec<ListenEvent>, Error> {
    let mut events = Vec::new();
    if let Some(name) = force_name {
        let ops = select_stores(incoming, config, Some(name))?;
        for op in ops {
            events.push(persist(vault, &op)?);
        }
        return Ok(events);
    }
    for msg in incoming {
        match ingest(vault, config, msg)? {
            ListenEvent::Ignored { .. } => {}
            event => events.push(event),
        }
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;
    use crate::vault::Vault;
    use tempfile::TempDir;

    fn msg(body: &str, sync: bool) -> Incoming {
        Incoming {
            sender_number: Some("+15551234567".into()),
            sender_uuid: None,
            body: body.into(),
            is_sync: sync,
            is_group: false,
        }
    }

    fn setup() -> (TempDir, Config, Vault) {
        let dir = TempDir::new().unwrap();
        let paths = Paths::new(dir.path().join("hush"));
        Vault::init(&paths).unwrap();
        let mut config = Config::default();
        config.signal.account = Some("+15551234567".into());
        let vault = Vault::open(&paths).unwrap();
        (dir, config, vault)
    }

    #[test]
    fn named_pull_takes_latest_plain_secret() {
        let (_dir, config, vault) = setup();
        let incoming = vec![
            msg("old", true),
            msg("hush: stored ignore-me", true),
            msg("sk-live-NOT-IN-CHAT", true),
        ];
        let events = pull_from_incoming(&vault, &config, &incoming, Some("stripe-prod")).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ListenEvent::Stored { name, sender, .. } => {
                assert_eq!(name, "stripe-prod");
                assert_eq!(sender, "self");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            &vault.get("stripe-prod").unwrap()[..],
            b"sk-live-NOT-IN-CHAT"
        );
        let dumped = serde_json::to_string(&events).unwrap();
        assert!(!dumped.contains("sk-live"));
    }

    #[test]
    fn unnamed_pull_only_protocol_messages() {
        let (_dir, config, vault) = setup();
        let incoming = vec![
            msg("random chatter", true),
            msg("hush put github-pat\nghp_secret", true),
        ];
        let events = pull_from_incoming(&vault, &config, &incoming, None).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(&vault.get("github-pat").unwrap()[..], b"ghp_secret");
        assert!(vault.get("random").is_err());
    }

    #[test]
    fn skips_acks_when_naming() {
        let incoming = vec![msg("hush: stored stripe-prod", true)];
        let config = {
            let mut config = Config::default();
            config.signal.account = Some("+15551234567".into());
            config
        };
        let ops = select_stores(&incoming, &config, Some("stripe-prod")).unwrap();
        assert!(ops.is_empty());
    }
}
