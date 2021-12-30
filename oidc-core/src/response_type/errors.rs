use thiserror::Error;

use oidc_types::jose::error::JWTError;
use oidc_types::response_type::ResponseType;

use crate::hash::HashingError;
use crate::id_token::IdTokenError;

#[derive(Error, Debug)]
pub enum AuthorisationError {
    #[error("Missing required response_type in authorisation request")]
    MissingResponseType,
    #[error("Missing required state parameter in authorisation request")]
    MissingState,
    #[error("response_type {} not configured for this provider or not allowed for client {}", .0, .1)]
    ResponseTypeNotAllowed(ResponseType, String),
    #[error("response_type {} not configured for this provider", .0)]
    ResponseTypeResolveNotConfigured(ResponseType),
    #[error("Missing signing key configuration in jwks")]
    SigningKeyNotConfigured,
    #[error("Error creating id_token")]
    IdTokenCreationError {
        #[from]
        source: IdTokenError
    },
    #[error("Error hashing {}", .prop)]
    HashingErr {
        prop: String,
        #[source]
        source: HashingError,
    },
}