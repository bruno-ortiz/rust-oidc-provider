use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{FromRef, FromRequest, FromRequestParts};
use axum::http::{HeaderMap, Request};
use axum::response::{IntoResponse, Response};
use serde::de::value::Error as SerdeError;
use serde::de::DeserializeOwned;
use serde_urlencoded::from_bytes;
use thiserror::Error;
use tracing::error;

use oidc_core::client::{retrieve_client_info, ClientError};
use oidc_core::client_auth::{ClientAuthenticationError, ClientAuthenticator};
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::error::OpenIdError;
use oidc_core::models::client::AuthenticatedClient;
use oidc_core::services::keystore::KeystoreService;
use oidc_types::auth_method::AuthMethod;
use oidc_types::client::ClientID;

use crate::credentials::{Credentials, CredentialsError};
use crate::routes::error::OpenIdErrorResponse;
use crate::state::AppState;

#[derive(Debug, Error)]
pub enum AuthenticatedRequestError {
    #[error("Error reading request body, {}", .0)]
    ReadRequest(#[from] BytesRejection),
    #[error(transparent)]
    Credentials(#[from] CredentialsError),
    #[error("Error parsing body params, {:?}", .0)]
    ParseBody(#[from] SerdeError),
    #[error("Error getting client: {}", .0)]
    FindClient(#[from] ClientError),
    #[error("Unknown client: {}", .0)]
    InvalidClient(ClientID),
    #[error("Auth method not allowed for client. Auth Method: {}", .0)]
    AuthMethodNotAllowed(AuthMethod),
    #[error("Credential not found in request for auth Method: {}", .0)]
    CredentialsNotFound(AuthMethod),
    #[error(transparent)]
    AuthenticationFailed(#[from] ClientAuthenticationError),
}

impl IntoResponse for AuthenticatedRequestError {
    fn into_response(self) -> Response {
        error!("{:?}", self);
        let openid_error = match self {
            AuthenticatedRequestError::Credentials(err) => err.into(),
            AuthenticatedRequestError::ReadRequest(err) => OpenIdError::server_error(err),
            AuthenticatedRequestError::ParseBody(_) => {
                OpenIdError::invalid_request("Error parsing body params")
            }
            AuthenticatedRequestError::FindClient(_) => {
                OpenIdError::invalid_client("Error looking for openid client")
            }
            AuthenticatedRequestError::InvalidClient(_) => {
                OpenIdError::invalid_client("Unknown openid client")
            }
            AuthenticatedRequestError::AuthMethodNotAllowed(_) => {
                OpenIdError::invalid_client("Auth method not allowed for client")
            }
            AuthenticatedRequestError::AuthenticationFailed(_) => {
                OpenIdError::invalid_client("Authentication failed")
            }
            AuthenticatedRequestError::CredentialsNotFound(_) => {
                OpenIdError::invalid_request("Credential not found in request")
            }
        };
        OpenIdErrorResponse::from(openid_error).into_response()
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedRequest<B> {
    pub authenticated_client: AuthenticatedClient,
    pub body: B,
}

#[async_trait]
impl<B> FromRequest<AppState, axum::body::Body> for AuthenticatedRequest<B>
where
    B: DeserializeOwned,
{
    type Rejection = AuthenticatedRequestError;

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();

        let headers = HeaderMap::from_request_parts(&mut parts, state)
            .await
            .expect("Expected to be infallible");
        let provider = parts
            .extensions
            .get::<Arc<OpenIDProviderConfiguration>>()
            .cloned()
            .expect("Error getting provider from extensions");
        let req = Request::from_parts(parts, body);
        let body_bytes = Bytes::from_request(req, state).await?;
        let mut credentials =
            Credentials::parse_credentials(&headers, &body_bytes, &provider).await?;
        let client = retrieve_client_info(&provider, credentials.client_id)
            .await?
            .ok_or_else(|| AuthenticatedRequestError::InvalidClient(credentials.client_id))?;
        let auth_method = client.metadata().token_endpoint_auth_method;
        if !provider
            .token_endpoint_auth_methods_supported()
            .contains(&auth_method)
        {
            return Err(AuthenticatedRequestError::AuthMethodNotAllowed(auth_method));
        }

        let credential = credentials
            .take(&auth_method)
            .ok_or_else(|| AuthenticatedRequestError::CredentialsNotFound(auth_method))?;

        let keystore_service: Arc<KeystoreService> = FromRef::from_ref(state);
        let client = credential
            .authenticate(&provider, &keystore_service, client)
            .await?;

        let token_request = from_bytes::<B>(&body_bytes)?;
        Ok(AuthenticatedRequest {
            authenticated_client: client,
            body: token_request,
        })
    }
}
