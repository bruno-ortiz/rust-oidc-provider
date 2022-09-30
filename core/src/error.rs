use std::fmt::{Display, Formatter};

use indexmap::IndexMap;
use serde::Serialize;
use thiserror::Error;

use oidc_types::scopes::{Scope, Scopes};
use oidc_types::url_encodable::UrlEncodable;

use crate::adapter::PersistenceError;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenIdErrorType {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
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
            OpenIdErrorType::InvalidClient => write!(f, "invalid_client"),
            OpenIdErrorType::UnsupportedGrantType => write!(f, "unsupported_grant_type"),
            OpenIdErrorType::InvalidGrant => write!(f, "invalid_grant"),
        }
    }
}

#[derive(Error, Debug, Serialize)]
#[error("OpenId error: {:?}, description: {}", .error_type, .description)]
pub struct OpenIdError {
    #[serde(rename = "error")]
    error_type: OpenIdErrorType,
    #[serde(rename = "error_description")]
    description: String,
    #[serde(skip)]
    source: Option<anyhow::Error>,
}

impl OpenIdError {
    fn new<D: Into<String>>(
        error_type: OpenIdErrorType,
        description: D,
        source: Option<anyhow::Error>,
    ) -> Self {
        Self {
            error_type,
            description: description.into(),
            source,
        }
    }

    pub fn invalid_request<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::InvalidRequest, description, None)
    }

    pub fn invalid_grant<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::InvalidGrant, description, None)
    }

    pub fn invalid_client<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::InvalidRequest, description, None)
    }

    pub fn invalid_scope(scope: &Scope) -> Self {
        Self::new(
            OpenIdErrorType::InvalidScope,
            format!("Invalid scope {}", scope),
            None,
        )
    }

    pub fn invalid_scopes(scope: &Scopes) -> Self {
        Self::new(
            OpenIdErrorType::InvalidScope,
            format!("Invalid scope {}", scope),
            None,
        )
    }

    pub fn unsupported_grant_type<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::UnsupportedGrantType, description, None)
    }

    pub fn unsupported_response_type<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::UnsupportedResponseType, description, None)
    }

    pub fn unauthorized_client<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::UnauthorizedClient, description, None)
    }

    pub fn server_error<T>(source: T) -> Self
    where
        T: Into<anyhow::Error>,
    {
        let error = source.into();
        Self::new(OpenIdErrorType::ServerError, error.to_string(), Some(error))
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

impl From<PersistenceError> for OpenIdError {
    fn from(err: PersistenceError) -> Self {
        OpenIdError::server_error(err)
    }
}
