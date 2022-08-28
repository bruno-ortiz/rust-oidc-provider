use rand::Rng;

use crate::password_hasher::{HashingError, PasswordHasher};
use std::fmt::{Display, Formatter};
use tracing::error;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                         abcdefghijklmnopqrstuvwxyz\
                         0123456789)(*&^%$#@!~";
const PASSWORD_LEN: usize = 20;

#[derive(Debug, Clone)]
pub struct HashedSecret(String);

#[derive(Debug, Clone)]
pub struct PlainTextSecret(String);

impl HashedSecret {
    pub fn random<H: PasswordHasher>(hasher: H) -> Result<(Self, PlainTextSecret), HashingError> {
        let secret = random_pwd(CHARSET, PASSWORD_LEN);
        let hashed_secret = Self(hasher.hash(secret.as_bytes())?);
        let plain_secret = PlainTextSecret(secret);
        Ok((hashed_secret, plain_secret))
    }

    pub fn verify<H: PasswordHasher, P: AsRef<[u8]>>(&self, hasher: H, pwd: P) -> bool {
        hasher
            .verify(self.0.as_bytes(), pwd.as_ref())
            .unwrap_or_else(|err| {
                error!("Error verifying hash: {}", err);
                false
            })
    }
}

impl Display for HashedSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for PlainTextSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<String> for HashedSecret {
    fn eq(&self, other: &String) -> bool {
        *other == self.0
    }
}

fn random_pwd(charset: &[u8], len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::hashed_secret::HashedSecret;
    use crate::password_hasher::HasherConfig;

    #[test]
    fn test_can_verify_pwd() {
        let (hashed, plain) = HashedSecret::random(HasherConfig::Sha256).unwrap();

        assert!(hashed.verify(HasherConfig::Sha256, plain.to_string().as_str()))
    }

    #[test]
    fn test_fails_with_invalid_pwd() {
        let (hashed, _) = HashedSecret::random(HasherConfig::Sha256).unwrap();

        assert!(!hashed.verify(HasherConfig::Sha256, "invalid"))
    }
}
