use crate::Error;

pub fn parse_name(raw: &str) -> Result<String, Error> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(Error::InvalidName("empty".into()));
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(Error::InvalidName("empty".into()));
    };
    if !first.is_ascii_alphabetic() {
        return Err(Error::InvalidName(
            "must start with a letter (A-Z or a-z)".into(),
        ));
    }
    if name.len() > 64 {
        return Err(Error::InvalidName("longer than 64 characters".into()));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
        return Err(Error::InvalidName(
            "use only letters, digits, '.', '_' and '-'".into(),
        ));
    }
    if name.contains("..") {
        return Err(Error::InvalidName("must not contain '..'".into()));
    }
    Ok(name.to_string())
}

/// A hush box address. `robin` and `robin@hush.sh` are the same address.
pub fn parse_box_address(raw: &str) -> Result<String, Error> {
    let raw = raw.trim();
    let local = if let Some(local) = raw.strip_suffix("@hush.sh") {
        local
    } else if raw.contains('@') {
        return Err(Error::InvalidName(
            "box addresses use @hush.sh, for example robin@hush.sh".into(),
        ));
    } else {
        raw
    };
    let local = parse_name(local)?;
    Ok(format!("{local}@hush.sh"))
}

pub fn parse_env_name(raw: &str) -> Result<String, Error> {
    let name = raw.trim();
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(Error::InvalidEnv("empty".into()));
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(Error::InvalidEnv(name.into()));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(Error::InvalidEnv(name.into()));
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple_names() {
        assert_eq!(parse_name("stripe-prod").unwrap(), "stripe-prod");
        assert_eq!(parse_name("GitHub_PAT").unwrap(), "GitHub_PAT");
        assert_eq!(parse_name("v1.token").unwrap(), "v1.token");
    }

    #[test]
    fn rejects_paths_and_junk() {
        assert!(parse_name("../etc").is_err());
        assert!(parse_name("foo/bar").is_err());
        assert!(parse_name("").is_err());
        assert!(parse_name("1abc").is_err());
        assert!(parse_name("has space").is_err());
        assert_eq!(
            parse_box_address("robin").unwrap(),
            "robin@hush.sh"
        );
        assert_eq!(
            parse_box_address("robin@hush.sh").unwrap(),
            "robin@hush.sh"
        );
        assert!(parse_box_address("robin@example.com").is_err());
    }

    #[test]
    fn env_names() {
        assert_eq!(parse_env_name("STRIPE_API_KEY").unwrap(), "STRIPE_API_KEY");
        assert!(parse_env_name("1FOO").is_err());
        assert!(parse_env_name("FOO-BAR").is_err());
    }
}
