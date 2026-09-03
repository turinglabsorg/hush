use crate::bitwarden::{self, VaultItem};
use crate::config::Config;
use crate::listen::{emit, ListenEvent};
use crate::name::parse_name;
use crate::paths::Paths;
use crate::protocol::{parse_body, value_from_body, Ingest};
use crate::vault::Vault;
use crate::Error;

pub struct PullOptions {
    pub name: Option<String>,
    pub send_url: Option<String>,
    /// Passthrough flags for `bw send receive` (`--passwordenv VAR`,
    /// `--passwordfile PATH`). Never a literal password.
    pub send_auth: Vec<String>,
    pub consume: bool,
    pub json: bool,
}

/// Store a Send received by URL under `name`. The URL is not secret;
/// the Send content is validated and never printed.
fn pull_send(
    vault: &Vault,
    name: &str,
    url: &str,
    send_auth: &[String],
    json: bool,
) -> Result<(), Error> {
    let name = parse_name(name)?;
    let raw = bitwarden::send_receive(url, send_auth)?;
    let text = String::from_utf8(raw)
        .map_err(|_| Error::user("Send is not valid UTF-8; hush only stores text secrets"))?;
    let value = value_from_body(&text).map_err(Error::user)?;
    let replaced = vault.info(&name).is_ok();
    vault.put(&name, &value, "bitwarden-send", "self")?;
    emit(
        &ListenEvent::Stored {
            name,
            sender: "self".into(),
            replaced,
        },
        json,
    );
    Ok(())
}

/// Store a vault item's password/notes verbatim under `wanted`.
fn store_exact(vault: &Vault, wanted: &str, item: &VaultItem, json: bool) -> Result<(), Error> {
    let name = parse_name(wanted)?;
    let secret = bitwarden::item_secret(item)?;
    let text = String::from_utf8(secret)
        .map_err(|_| Error::user("vault item is not valid UTF-8; hush only stores text secrets"))?;
    let value = value_from_body(&text).map_err(Error::user)?;
    let replaced = vault.info(&name).is_ok();
    vault.put(&name, &value, "bitwarden", "self")?;
    emit(
        &ListenEvent::Stored {
            name,
            sender: "self".into(),
            replaced,
        },
        json,
    );
    Ok(())
}

/// Ingest one vault item whose name carries the `hush put NAME` command.
/// The item secret is validated by the protocol parser and never printed.
pub fn ingest_item(vault: &Vault, item: &VaultItem) -> Result<ListenEvent, Error> {
    let secret = match bitwarden::item_secret(item) {
        Ok(secret) => secret,
        Err(_) => {
            return Ok(ListenEvent::Ignored {
                reason: format!("item `{}` has no password or notes", item.name),
            });
        }
    };
    let text = String::from_utf8(secret)
        .map_err(|_| Error::user("vault item is not valid UTF-8; hush only stores text secrets"))?;
    match parse_body(&format!("{}\n{}", item.name, text)) {
        Ingest::NotForUs => Ok(ListenEvent::Ignored {
            reason: format!("item `{}` is not a hush put item", item.name),
        }),
        Ingest::Error(reason) => Ok(ListenEvent::Rejected { reason }),
        Ingest::Put { name, value } => {
            let replaced = vault.info(&name).is_ok();
            vault.put(&name, &value, "bitwarden", "self")?;
            Ok(ListenEvent::Stored {
                name,
                sender: "self".into(),
                replaced,
            })
        }
    }
}

/// Does this vault item name address secret `wanted`?
/// Matches `hush put WANTED` (or `/hush ...`, `replace`) via the protocol parser.
pub fn item_addresses(item_name: &str, wanted: &str) -> bool {
    match parse_body(&format!("{item_name}\nplaceholder")) {
        Ingest::Put { name, .. } => name.eq_ignore_ascii_case(wanted),
        _ => false,
    }
}

/// Pick the best vault item for `wanted`: an exact name match first,
/// then a `hush put WANTED` command item.
pub fn pick_item<'a>(items: &'a [VaultItem], wanted: &str) -> Option<(&'a VaultItem, bool)> {
    if let Some(item) = items
        .iter()
        .find(|item| item.name.eq_ignore_ascii_case(wanted))
    {
        return Some((item, true));
    }
    items
        .iter()
        .find(|item| item_addresses(&item.name, wanted))
        .map(|item| (item, false))
}

fn pull_named(vault: &Vault, wanted: &str, consume: bool, json: bool) -> Result<(), Error> {
    bitwarden::sync()?;
    let items = bitwarden::list_items(Some(wanted))?;
    let (picked, is_exact) = pick_item(&items, wanted).ok_or_else(|| {
        Error::NotFound(format!(
            "{wanted} (no vault item or `hush put {wanted}` found; share one via Bitwarden Send and retry with `--send URL`)"
        ))
    })?;
    let item = bitwarden::get_item(&picked.id)?;
    if is_exact {
        store_exact(vault, wanted, &item, json)?;
    } else {
        match ingest_item(vault, &item)? {
            ListenEvent::Ignored { .. } => return Err(Error::NotFound(wanted.to_string())),
            event => emit(&event, json),
        }
    }
    if consume {
        bitwarden::delete_item(&item.id)?;
    }
    Ok(())
}

fn pull_scan(vault: &Vault, consume: bool, json: bool) -> Result<(), Error> {
    bitwarden::sync()?;
    let items = bitwarden::list_items(Some("hush put"))?;
    let mut stored = 0;
    for item in &items {
        match ingest_item(vault, item)? {
            ListenEvent::Ignored { .. } => {}
            event => {
                if consume {
                    if let ListenEvent::Stored { .. } = &event {
                        bitwarden::delete_item(&item.id)?;
                    }
                }
                emit(&event, json);
                stored += 1;
            }
        }
    }
    if stored == 0 {
        return Err(Error::user(
            "no `hush put NAME` items found in the Bitwarden vault; share one via Send (`hush pull --name NAME --send URL`) or add a vault item named `hush put NAME`",
        ));
    }
    Ok(())
}

pub fn pull(paths: &Paths, opts: &PullOptions) -> Result<(), Error> {
    let config = Config::load(paths)?;
    let vault = Vault::open(paths)?;
    let consume = opts.consume || config.bitwarden.consume_after_pull;
    if let Some(url) = opts.send_url.clone() {
        let Some(name) = opts.name.clone() else {
            return Err(Error::user("`--send URL` requires `--name NAME`"));
        };
        return pull_send(&vault, &name, &url, &opts.send_auth, opts.json);
    }
    if let Some(name) = opts.name.clone() {
        return pull_named(&vault, &name, consume, opts.json);
    }
    pull_scan(&vault, consume, opts.json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitwarden::ItemLogin;
    use tempfile::TempDir;

    fn item(id: &str, name: &str) -> VaultItem {
        VaultItem {
            id: id.into(),
            name: name.into(),
            login: None,
            notes: None,
        }
    }

    #[test]
    fn picks_exact_before_command() {
        let items = vec![
            item("1", "hush put db"),
            item("2", "db"),
            item("3", "other"),
        ];
        let (picked, is_exact) = pick_item(&items, "db").unwrap();
        assert_eq!(picked.id, "2");
        assert!(is_exact);
    }

    #[test]
    fn picks_command_item() {
        let items = vec![item("1", "hush put db"), item("3", "other")];
        let (picked, is_exact) = pick_item(&items, "db").unwrap();
        assert_eq!(picked.id, "1");
        assert!(!is_exact);
    }

    #[test]
    fn no_match_returns_none() {
        let items = vec![item("1", "hush put db")];
        assert!(pick_item(&items, "nope").is_none());
    }

    #[test]
    fn ingests_command_item_without_echoing_secret() {
        let dir = TempDir::new().unwrap();
        let paths = Paths::new(dir.path().join("hush"));
        Vault::init(&paths).unwrap();
        let vault = Vault::open(&paths).unwrap();
        let item = VaultItem {
            id: "1".into(),
            name: "hush put stripe-prod".into(),
            login: Some(ItemLogin {
                password: Some("sk-live-NOT-IN-CHAT".into()),
            }),
            notes: None,
        };
        let event = ingest_item(&vault, &item).unwrap();
        match &event {
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
        let dumped = serde_json::to_string(&event).unwrap();
        assert!(!dumped.contains("sk-live"));
    }

    #[test]
    fn ignores_plain_items() {
        let dir = TempDir::new().unwrap();
        let paths = Paths::new(dir.path().join("hush"));
        Vault::init(&paths).unwrap();
        let vault = Vault::open(&paths).unwrap();
        let item = VaultItem {
            id: "1".into(),
            name: "random chatter".into(),
            login: None,
            notes: Some("hello".into()),
        };
        let event = ingest_item(&vault, &item).unwrap();
        assert!(matches!(event, ListenEvent::Ignored { .. }));
    }
}
