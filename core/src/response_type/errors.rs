use indexmap::IndexMap;
use std::fmt::{Display, Formatter};

use oidc_types::scopes::Scope;
use thiserror::Error;

use oidc_types::url_encodable::UrlEncodable;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum OpenIdErrorType {
    InvalidRequest,
    UnauthorizedClient,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
}

impl Display for OpenIdErrorType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenIdErrorType::InvalidRequest => write!(f, "invalid_request"),
            OpenIdErrorType::UnauthorizedClient => write!(f, "unauthorized_client"),
            OpenIdErrorType::UnsupportedResponseType => write!(f, "unsupported_response_type"),
            OpenIdErrorType::InvalidScope => write!(f, "invalid_scope"),
            OpenIdErrorType::ServerError => write!(f, "server_error"),
            OpenIdErrorType::TemporarilyUnavailable => write!(f, "temporary_unavailable"),
        }
    }
}

#[derive(Error, Debug)]
#[error("OpenId error: {:?}, description: {}", .error_type, .description)]
pub struct OpenIdError {
    error_type: OpenIdErrorType,
    description: String,
}

impl OpenIdError {
    pub fn new<D: Into<String>>(error_type: OpenIdErrorType, description: D) -> Self {
        Self {
            error_type,
            description: description.into(),
        }
    }

    pub fn invalid_request<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::InvalidRequest, description)
    }

    pub fn invalid_scope(scope: &Scope) -> Self {
        Self::new(
            OpenIdErrorType::InvalidScope,
            format!("Invalid scope {}", scope),
        )
    }

    pub fn unsupported_response_type<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::UnsupportedResponseType, description)
    }

    pub fn unauthorized_client<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::UnauthorizedClient, description)
    }

    pub fn server_error(source: anyhow::Error) -> Self {
        Self::new(OpenIdErrorType::ServerError, source.to_string())
    }

    pub fn error_type(&self) -> OpenIdErrorType {
        self.error_type
    }
}

impl UrlEncodable for OpenIdError {
    fn params(self) -> IndexMap<String, String> {
        let mut parameters = IndexMap::new();
        parameters.insert("error".to_owned(), self.error_type.to_string());
        parameters.insert("error_description".to_owned(), self.description);
        parameters
    }
}
