use thiserror::Error;

use oidc_types::jose::error::JWTError;

#[derive(Debug, Error)]
pub enum EncodingError {
    #[error("Missing signing key configuration in jwks")]
    MissingSigningKey,
    #[error("Error creating JWT: {}", .0)]
    JwtCreationError(JWTError),
    #[error("Internal error: {}", .0)]
    InternalError(String)
}
