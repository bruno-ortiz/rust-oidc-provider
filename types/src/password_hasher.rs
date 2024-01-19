use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::{DecodeError, Engine};
use rand::Rng;
use sha2::{Digest, Sha256};
use thiserror::Error;

const SALT_LEN: usize = 16;

#[derive(Debug, Error, Clone)]
pub enum HashingError {
    #[error("Error decoding hash: {}", .0)]
    DecodeError(#[from] DecodeError),
}

pub trait PasswordHasher {
    fn hash(&self, pwd: &[u8]) -> Result<String, HashingError>;

    fn verify(&self, hash: &[u8], pwd: &[u8]) -> Result<bool, HashingError>;
}

#[derive(Copy, Clone)]
struct SHA256Hasher;

impl PasswordHasher for SHA256Hasher {
    fn hash(&self, pwd: &[u8]) -> Result<String, HashingError> {
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt);
        let hash = &Sha256::digest([&salt, pwd].concat())[..];
        Ok(base64_engine.encode([&salt, hash].concat()))
    }

    fn verify(&self, hash: &[u8], pwd: &[u8]) -> Result<bool, HashingError> {
        let decoded = base64_engine.decode(hash)?;
        let salt = &decoded[0..SALT_LEN];
        let hash = &decoded[SALT_LEN..];

        let pwd_hash = &Sha256::digest([salt, pwd].concat())[..];

        Ok(hash == pwd_hash)
    }
}

#[derive(Copy, Clone)]
pub enum HasherConfig {
    Sha256,
}

impl PasswordHasher for HasherConfig {
    #[inline]
    fn hash(&self, pwd: &[u8]) -> Result<String, HashingError> {
        match self {
            HasherConfig::Sha256 => SHA256Hasher.hash(pwd),
        }
    }
    #[inline]
    fn verify(&self, hash: &[u8], pwd: &[u8]) -> Result<bool, HashingError> {
        match self {
            HasherConfig::Sha256 => SHA256Hasher.verify(hash, pwd),
        }
    }
}
