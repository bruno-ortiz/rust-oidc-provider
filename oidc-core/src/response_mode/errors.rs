use josekit::JoseError;
use thiserror::Error;

use oidc_types::client::ClientID;
use oidc_types::jose::error::JWTError;

#[derive(Debug, Error)]
pub enum EncodingError {
    #[error("Missing redirect uri for client: {}", .0)]
    MissingRedirectUri(ClientID),
    #[error("Missing signing key")]
    MissingSigningKey,
    #[error("Error creating JWT: {}", .0)]
    JwtCreationError(JWTError),
}
