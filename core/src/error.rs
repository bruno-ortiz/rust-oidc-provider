use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::request_object::Error as RequestObjectError;
use indexmap::IndexMap;
use serde::Serialize;
use thiserror::Error;

use oidc_types::scopes::Scopes;
use oidc_types::url_encodable::UrlEncodable;

use crate::adapter::PersistenceError;
use crate::client::ClientError;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenIdErrorType {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    LoginRequired,
    ConsentRequired,
    UnsupportedGrantType,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
    InvalidToken,
    InsufficientScope,
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
            OpenIdErrorType::LoginRequired => write!(f, "login_required"),
            OpenIdErrorType::ConsentRequired => write!(f, "consent_required"),
            OpenIdErrorType::InvalidToken => write!(f, "invalid_token"),
            OpenIdErrorType::InsufficientScope => write!(f, "insufficient_scope"),
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
    #[source]
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

    pub fn invalid_request_with_source<D: Into<String>, T: Into<anyhow::Error>>(
        description: D,
        source: T,
    ) -> Self {
        Self::new(
            OpenIdErrorType::InvalidRequest,
            description,
            Some(source.into()),
        )
    }

    pub fn invalid_grant<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::InvalidGrant, description, None)
    }

    pub fn invalid_grant_with_source<D: Into<String>, T: Into<anyhow::Error>>(
        description: D,
        source: T,
    ) -> Self {
        Self::new(
            OpenIdErrorType::InvalidGrant,
            description,
            Some(source.into()),
        )
    }

    pub fn invalid_client<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::InvalidClient, description, None)
    }

    pub fn invalid_client_with_source<D: Into<String>, T: Into<anyhow::Error>>(
        description: D,
        source: T,
    ) -> Self {
        Self::new(
            OpenIdErrorType::InvalidClient,
            description,
            Some(source.into()),
        )
    }

    pub fn invalid_scope<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::InvalidScope, description, None)
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

    pub fn login_required<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::LoginRequired, description, None)
    }

    pub fn consent_required<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::ConsentRequired, description, None)
    }

    pub fn invalid_token<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::InvalidToken, description, None)
    }

    pub fn invalid_token_with_source<D: Into<String>, T: Into<anyhow::Error>>(
        description: D,
        source: T,
    ) -> Self {
        Self::new(
            OpenIdErrorType::InvalidToken,
            description,
            Some(source.into()),
        )
    }

    pub fn insufficient_scope<D: Into<String>>(description: D) -> Self {
        Self::new(OpenIdErrorType::InsufficientScope, description, None)
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

impl From<ClientError> for OpenIdError {
    fn from(err: ClientError) -> Self {
        OpenIdError::server_error(err)
    }
}

impl From<anyhow::Error> for OpenIdError {
    fn from(err: anyhow::Error) -> Self {
        OpenIdError::server_error(err)
    }
}

impl From<RequestObjectError> for OpenIdError {
    fn from(err: RequestObjectError) -> Self {
        match err {
            RequestObjectError::InvalidRequestObject(_) => {
                OpenIdError::invalid_request_with_source("Invalid request_object", err)
            }
            RequestObjectError::RequestObjAndUri => OpenIdError::invalid_request_with_source(
                "Request object and request_uri are both present",
                err,
            ),
            RequestObjectError::MissingAlg => {
                OpenIdError::invalid_request_with_source("Request object is missing alg", err)
            }
            RequestObjectError::AlgMismatch(_, _) => {
                OpenIdError::invalid_request_with_source("Request object alg mismatch", err)
            }
            RequestObjectError::UnsignedRequestObject => {
                OpenIdError::invalid_request_with_source("Request object must be signed", err)
            }
            RequestObjectError::Internal(_) => OpenIdError::server_error(err),
        }
    }
}

pub fn build_report<E>(err: &E) -> String
where
    E: std::error::Error,
    E: Send + Sync,
{
    let mut count = 0;
    let mut current_err: &dyn Error = err;
    let mut report = format!("[ERROR] - {}", current_err);
    if current_err.source().is_some() {
        report.push_str("\nCaused by:");
    }
    while let Some(cause) = current_err.source() {
        count += 1;
        report.push_str(&format!("\n    {}: {}", count, cause));
        current_err = cause;
    }
    report
}
