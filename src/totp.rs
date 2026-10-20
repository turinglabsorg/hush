use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use url::Url;
use zeroize::Zeroizing;

use crate::Error;

enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Totp {
    key: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

impl Totp {
    pub fn parse(input: &str) -> Result<Self, Error> {
        let input = input.trim();
        if input.len() > 8192 {
            return Err(Error::user("TOTP enrollment exceeds 8 KiB"));
        }
        let mut digits = 6;
        let mut period = 30;
        let mut algorithm = Algorithm::Sha1;
        let mut seed = Zeroizing::new(input.to_owned());
        if input.starts_with("otpauth:") {
            let uri = Url::parse(input).map_err(|_| Error::user("invalid TOTP enrollment URI"))?;
            if uri.scheme() != "otpauth"
                || uri.host_str() != Some("totp")
                || !uri.username().is_empty()
                || uri.password().is_some()
                || uri.port().is_some()
                || uri.fragment().is_some()
            {
                return Err(Error::user("expected an otpauth://totp enrollment URI"));
            }
            seed.clear();
            let mut seen = HashSet::new();
            for (key, value) in uri.query_pairs() {
                if ["secret", "algorithm", "digits", "period"].contains(&key.as_ref())
                    && !seen.insert(key.to_string())
                {
                    return Err(Error::user("duplicate TOTP enrollment parameter"));
                }
                match key.as_ref() {
                    "secret" => seed.push_str(&value),
                    "algorithm" => {
                        algorithm = match value.to_ascii_uppercase().as_str() {
                            "SHA1" => Algorithm::Sha1,
                            "SHA256" => Algorithm::Sha256,
                            "SHA512" => Algorithm::Sha512,
                            _ => return Err(Error::user("unsupported TOTP algorithm")),
                        }
                    }
                    "digits" => {
                        digits = value
                            .parse()
                            .map_err(|_| Error::user("invalid TOTP digit count"))?
                    }
                    "period" => {
                        period = value
                            .parse()
                            .map_err(|_| Error::user("invalid TOTP period"))?
                    }
                    _ => {}
                }
            }
        }
        if ![6, 8].contains(&digits) || !(15..=120).contains(&period) {
            return Err(Error::user(
                "TOTP requires 6 or 8 digits and a period of 15 to 120 seconds",
            ));
        }
        let normalized = Zeroizing::new(
            seed.chars()
                .filter(|c| !c.is_ascii_whitespace())
                .map(|c| c.to_ascii_uppercase())
                .collect::<String>(),
        );
        let key = Zeroizing::new(
            BASE32_NOPAD
                .decode(normalized.trim_end_matches('=').as_bytes())
                .map_err(|_| Error::user("invalid TOTP base32 seed"))?,
        );
        if key.len() < 10 || key.len() > 128 {
            return Err(Error::user(
                "TOTP seed must contain 10 to 128 decoded bytes",
            ));
        }
        Ok(Self {
            key,
            algorithm,
            digits,
            period,
        })
    }

    pub fn at(&self, timestamp: u64) -> Result<Zeroizing<String>, Error> {
        let counter = (timestamp / self.period).to_be_bytes();
        macro_rules! sign {
            ($digest:ty) => {{
                let mut mac = Hmac::<$digest>::new_from_slice(&self.key)
                    .map_err(|_| Error::user("invalid TOTP signing key"))?;
                mac.update(&counter);
                mac.finalize().into_bytes().to_vec()
            }};
        }
        let digest = Zeroizing::new(match self.algorithm {
            Algorithm::Sha1 => sign!(Sha1),
            Algorithm::Sha256 => sign!(Sha256),
            Algorithm::Sha512 => sign!(Sha512),
        });
        let offset = (digest[digest.len() - 1] & 15) as usize;
        let binary =
            u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        Ok(Zeroizing::new(format!(
            "{:0width$}",
            binary % 10u32.pow(self.digits),
            width = self.digits as usize
        )))
    }

    pub fn current(&self) -> Result<Zeroizing<String>, Error> {
        let now = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::user("system clock precedes the Unix epoch"))
        };
        let time = now()?;
        let remaining = Duration::from_secs(self.period - time.as_secs() % self.period)
            .saturating_sub(Duration::from_nanos(time.subsec_nanos() as u64));
        if remaining < Duration::from_secs(10) {
            std::thread::sleep(remaining);
        }
        self.at(now()?.as_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_6238_appendix_b_for_all_algorithms_and_large_times() {
        let times = [
            59,
            1111111109,
            1111111111,
            1234567890,
            2000000000,
            20000000000,
        ];
        for (algorithm, key, expected) in [
            (
                "SHA1",
                "12345678901234567890",
                [
                    "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
                ],
            ),
            (
                "SHA256",
                "12345678901234567890123456789012",
                [
                    "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
                ],
            ),
            (
                "SHA512",
                "1234567890123456789012345678901234567890123456789012345678901234",
                [
                    "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
                ],
            ),
        ] {
            let uri = format!(
                "otpauth://totp/RFC?secret={}&algorithm={algorithm}&digits=8",
                BASE32_NOPAD.encode(key.as_bytes())
            );
            let totp = Totp::parse(&uri).unwrap();
            for (time, expected) in times.into_iter().zip(expected) {
                assert_eq!(totp.at(time).unwrap().as_str(), expected);
            }
        }
    }

    #[test]
    fn defaults_to_google_compatible_codes_and_preserves_leading_zeroes() {
        let totp = Totp::parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(totp.at(1111111109).unwrap().as_str(), "081804");
        assert_eq!(totp.at(59).unwrap().as_str(), "287082");
    }

    #[test]
    fn rejects_malformed_enrollments_without_echoing_them() {
        for input in [
            "private-invalid-seed!",
            "otpauth://hotp/private?secret=private",
            "otpauth://totp/private?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=9",
            "otpauth://totp/private?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=0",
            "otpauth://totp/private?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&secret=private",
            "otpauth://totp/private?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5",
        ] {
            let error = Totp::parse(input).err().expect("enrollment must fail");
            assert!(!error.to_string().contains(input));
            assert!(!error.to_string().contains("private"));
        }
    }
}
