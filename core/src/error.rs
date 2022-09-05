use indexmap::IndexMap;
use serde::Serialize;
use std::fmt::{Display, Formatter};

use oidc_types::scopes::{Scope, Scopes};
use thiserror::Error;

use oidc_types::url_encodable::UrlEncodable;

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
}

impl OpenIdError {
    fn new<D: Into<String>>(error_type: OpenIdErrorType, description: D) -> Self {
        Self {
            error_type,
            description: description.into(),
        }
    }

    pub fn invalid_request<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::InvalidRequest, description)
    }

    pub fn invalid_grant<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::InvalidGrant, description)
    }

    pub fn invalid_client<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::InvalidRequest, description)
    }

    pub fn invalid_scope(scope: &Scope) -> Self {
        Self::new(
            OpenIdErrorType::InvalidScope,
            format!("Invalid scope {}", scope),
        )
    }

    pub fn invalid_scopes(scope: &Scopes) -> Self {
        Self::new(
            OpenIdErrorType::InvalidScope,
            format!("Invalid scope {}", scope),
        )
    }

    pub fn unsupported_grant_type<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::UnsupportedGrantType, description)
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