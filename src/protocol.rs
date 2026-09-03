use crate::name::parse_name;
use crate::Error;

const MAX_SECRET_BYTES: usize = 256 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Ingest {
    Put { name: String, value: Vec<u8> },
    NotForUs,
    Error(String),
}

pub fn parse_body(text: &str) -> Ingest {
    let text = text.trim_start_matches('\u{feff}');
    let Some((first, rest)) = split_first_line(text) else {
        return Ingest::NotForUs;
    };
    let first = first.trim();
    let Some((verb, name_raw)) = parse_command(first) else {
        return Ingest::NotForUs;
    };
    if verb != "put" && verb != "replace" {
        return Ingest::Error(format!("unknown command `{verb}`"));
    }
    let name = match parse_name(&name_raw) {
        Ok(name) => name,
        Err(Error::InvalidName(reason)) => return Ingest::Error(reason),
        Err(_) => return Ingest::Error("invalid name".into()),
    };
    let mut value = rest.as_bytes().to_vec();
    if value.starts_with(b"\n") {
        value.remove(0);
    } else if value.starts_with(b"\r\n") {
        value.drain(0..2);
    }
    while value.last() == Some(&b'\n') || value.last() == Some(&b'\r') {
        value.pop();
    }
    if value.is_empty() {
        return Ingest::Error("missing secret body after hush put".into());
    }
    if value.contains(&0) {
        return Ingest::Error("secret must not contain NUL bytes".into());
    }
    if value.len() > MAX_SECRET_BYTES {
        return Ingest::Error("secret is larger than 256KiB".into());
    }
    Ingest::Put { name, value }
}

pub fn value_from_body(body: &str) -> Result<Vec<u8>, String> {
    let mut value = body.as_bytes().to_vec();
    while value.last() == Some(&b'\n') || value.last() == Some(&b'\r') {
        value.pop();
    }
    if value.is_empty() {
        return Err("empty secret".into());
    }
    if value.contains(&0) {
        return Err("secret must not contain NUL bytes".into());
    }
    if value.len() > MAX_SECRET_BYTES {
        return Err("secret is larger than 256KiB".into());
    }
    Ok(value)
}

fn split_first_line(text: &str) -> Option<(&str, &str)> {
    if text.is_empty() {
        return None;
    }
    match text.find('\n') {
        Some(idx) => {
            let (line, rest) = text.split_at(idx);
            let line = line.strip_suffix('\r').unwrap_or(line);
            Some((line, rest))
        }
        None => Some((text, "")),
    }
}

fn parse_command(first: &str) -> Option<(String, String)> {
    let first = first.trim();
    let lower = first.to_ascii_lowercase();
    let rest = if let Some(rest) = lower.strip_prefix("/hush ") {
        rest
    } else {
        lower.strip_prefix("hush ")?
    };
    let mut parts = rest.splitn(2, char::is_whitespace);
    let verb = parts.next()?.trim().to_string();
    let name = parts.next()?.trim().to_string();
    if name.is_empty() {
        return None;
    }
    Some((verb, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_single_line() {
        match parse_body("hush put stripe-prod\nsk-live-secret") {
            Ingest::Put { name, value } => {
                assert_eq!(name, "stripe-prod");
                assert_eq!(value, b"sk-live-secret");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn put_slash_prefix_and_replace() {
        match parse_body("/hush replace github-pat\ntok\n") {
            Ingest::Put { name, value } => {
                assert_eq!(name, "github-pat");
                assert_eq!(value, b"tok");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn put_multiline_keeps_inner_newlines() {
        match parse_body("hush put pem\n-----BEGIN\nABC\n-----END\n") {
            Ingest::Put { name, value } => {
                assert_eq!(name, "pem");
                assert_eq!(value, b"-----BEGIN\nABC\n-----END");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ignores_chat() {
        assert_eq!(parse_body("hello there"), Ingest::NotForUs);
        assert_eq!(parse_body("hush: stored stripe-prod"), Ingest::NotForUs);
    }

    #[test]
    fn empty_body_is_error() {
        assert!(matches!(parse_body("hush put foo"), Ingest::Error(_)));
        assert!(matches!(parse_body("hush put foo\n\n"), Ingest::Error(_)));
    }

    #[test]
    fn invalid_name_is_error() {
        assert!(matches!(
            parse_body("hush put ../x\nsecret"),
            Ingest::Error(_)
        ));
    }
}
