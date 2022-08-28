use crate::credentials::{Credentials, CredentialsError};
use async_trait::async_trait;
use axum::body::{Bytes, HttpBody};
use axum::extract::rejection::BytesRejection;
use axum::extract::{FromRequest, RequestParts};
use axum::response::{IntoResponse, Response};
use axum::{BoxError, Extension, Json};
use std::sync::Arc;

use crate::routes::error::OpenIdErrorResponse;
use oidc_core::client::retrieve_client_info;
use oidc_core::client_auth::ClientAuthenticator;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::error::OpenIdError;
use oidc_core::id_token::IdToken;
use oidc_core::token_resolver::TokenRequestResolver;
use oidc_types::access_token::AccessToken;
use oidc_types::auth_method::AuthMethod;
use oidc_types::token_request::TokenRequestBody;
use serde::de::value::Error as SerdeError;
use serde::Serialize;
use serde_urlencoded::from_bytes;
use serde_with::skip_serializing_none;
use thiserror::Error;
use tracing::error;

// #[axum_macros::debug_handler]
pub async fn token(
    request: TokenRequest,
    Extension(configuration): Extension<Arc<OpenIDProviderConfiguration>>,
) -> axum::response::Result<Json<TokenResponse>, OpenIdErrorResponse> {
    let mut credentials = request.credentials;
    let client = retrieve_client_info(&configuration, credentials.client_id)
        .await
        .ok_or_else(|| OpenIdError::invalid_client("Unknown client"))?;
    let auth_method = client
        .metadata
        .token_endpoint_auth_method
        .unwrap_or(AuthMethod::ClientSecretBasic);

    if !configuration
        .token_endpoint_auth_methods_supported()
        .contains(&auth_method)
    {
        return Err(OpenIdError::invalid_client(
            "unsupported authentication method",
        ))?;
    }
    let auth_method = credentials.take(&auth_method).ok_or_else(|| {
        OpenIdError::invalid_client("authentication method not allowed for client")
    })?;
    let client = auth_method
        .authenticate(&configuration, client)
        .await
        .map_err(|err| OpenIdError::invalid_client(err.to_string()))?;
    let access_token = request.body.execute(&configuration, client).await?;
    Ok(Json(TokenResponse {
        access_token,
        id_token: None,
    }))
}

#[derive(Debug, Error)]
pub enum TokenRequestError {
    #[error("Error reading request body, {}", .0)]
    ReadBody(#[from] BytesRejection),
    #[error(transparent)]
    Credentials(#[from] CredentialsError),
    #[error("Error parsing body params, {}", .0)]
    ParseBody(#[from] SerdeError),
}

impl IntoResponse for TokenRequestError {
    fn into_response(self) -> Response {
        let openid_error = match self {
            TokenRequestError::Credentials(err) => err.into(),
            TokenRequestError::ReadBody(err) => OpenIdError::server_error(err.into()),
            TokenRequestError::ParseBody(_) => {
                OpenIdError::invalid_request("Error parsing body params")
            }
        };
        OpenIdErrorResponse::from(openid_error).into_response()
    }
}

#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub credentials: Credentials,
    pub body: TokenRequestBody,
}

#[async_trait]
impl<B> FromRequest<B> for TokenRequest
where
    B: HttpBody + Send,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Rejection = TokenRequestError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(config) = Extension::<Arc<OpenIDProviderConfiguration>>::from_request(req)
            .await
            .expect("Config should always be present");
        let body_bytes = Bytes::from_request(req).await?;
        let headers = req.headers();
        let credentials = Credentials::parse_credentials(headers, &body_bytes, &config).await?;
        let token_request = from_bytes::<TokenRequestBody>(&body_bytes)?;
        Ok(TokenRequest {
            credentials,
            body: token_request,
        })
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    #[serde(flatten)]
    access_token: AccessToken,
    id_token: Option<IdToken>,
}
