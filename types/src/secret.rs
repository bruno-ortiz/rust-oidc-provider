use std::fmt::{Display, Formatter};

use rand::Rng;
use tracing::error;

use crate::password_hasher::{HashingError, PasswordHasher};

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                         abcdefghijklmnopqrstuvwxyz\
                         0123456789)(*&^%$#@!~";
pub const MIN_SECRET_LEN: usize = 32;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PlainTextSecret(String);

impl PlainTextSecret {
    pub fn size(&self) -> usize {
        self.0.as_bytes().len()
    }
}

impl PlainTextSecret {
    pub fn random() -> Self {
        PlainTextSecret(random_pwd(CHARSET, MIN_SECRET_LEN))
    }
}

impl AsRef<[u8]> for PlainTextSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsRef<str> for PlainTextSecret {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for PlainTextSecret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl Display for PlainTextSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<str> for PlainTextSecret {
    fn eq(&self, other: &str) -> bool {
        self.0.as_str() == other
    }
}

#[derive(Debug, Clone)]
pub struct HashedSecret(String);

impl HashedSecret {
    pub fn hash_string<H: PasswordHasher>(hasher: H, secret: &str) -> Result<Self, HashingError> {
        Ok(Self(hasher.hash(secret.as_bytes())?))
    }

    pub fn random<H: PasswordHasher>(hasher: H) -> Result<(Self, PlainTextSecret), HashingError> {
        let random_secret = random_pwd(CHARSET, MIN_SECRET_LEN);
        Self::hash_string(hasher, &random_secret).map(|hash| (hash, PlainTextSecret(random_secret)))
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

impl PartialEq<String> for HashedSecret {
    fn eq(&self, other: &String) -> bool {
        *other == self.0
    }
}

impl AsRef<[u8]> for HashedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<String> for HashedSecret {
    fn from(s: String) -> Self {
        Self(s)
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
    use crate::password_hasher::HasherConfig;
    use crate::secret::HashedSecret;

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
