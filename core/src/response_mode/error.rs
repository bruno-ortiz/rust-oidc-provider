use thiserror::Error;

use oidc_types::{jose::error::JWTError, response_mode::ResponseMode};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Missing signing key configuration in jwks")]
    MissingSigningKey,
    #[error("Missing encryption key in client JWKs")]
    MissingEncryptionKey,
    #[error("Error creating JWT: {}", .0)]
    JwtCreationError(#[from] JWTError),
    #[error("Invalid response mode: {0:?}")]
    InvalidResponseMode(ResponseMode),
    #[error(transparent)]
    InternalError(#[from] anyhow::Error),
}
