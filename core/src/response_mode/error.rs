use thiserror::Error;

use oidc_types::jose::error::JWTError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Missing signing key configuration in jwks")]
    MissingSigningKey,
    #[error("Error creating JWT: {}", .0)]
    JwtCreationError(JWTError),
    #[error(transparent)]
    InternalError(#[from] anyhow::Error),
}
