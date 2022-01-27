use std::collections::HashMap;

use thiserror::Error;

use oidc_types::response_type::ResponseType;
use oidc_types::scopes::Scope;
use oidc_types::url_encodable::UrlEncodable;

#[derive(Error, Debug)]
pub enum OpenIdError {
    #[error("Invalid request: {}", .description)]
    InvalidRequest { description: &'static str },
    #[error("Unauthorized client")]
    UnauthorizedClient {
        #[source]
        source: anyhow::Error,
    },
    #[error("Unsupported ResponseType: {}", .0)]
    UnsupportedResponseType(ResponseType),
    #[error("Invalid Scope: {}", .0)]
    InvalidScope(Scope),
    #[error("Internal error")]
    ServerError {
        #[source]
        source: anyhow::Error,
    },
    #[error("Temporary unavailable")]
    TemporarilyUnavailable,
}

impl UrlEncodable for OpenIdError {
    fn params(self) -> HashMap<String, String> {
        let mut parameters = HashMap::new();
        match self {
            OpenIdError::InvalidRequest { description } => {
                parameters.insert("error".to_owned(), "invalid_request".to_owned());
                parameters.insert("error_description".to_owned(), description.to_owned());
            }
            OpenIdError::UnauthorizedClient { .. } => todo!(),
            OpenIdError::UnsupportedResponseType(_) => todo!(),
            OpenIdError::InvalidScope(_) => todo!(),
            OpenIdError::ServerError { .. } => todo!(),
            OpenIdError::TemporarilyUnavailable => todo!(),
        }
        parameters
    }
}
