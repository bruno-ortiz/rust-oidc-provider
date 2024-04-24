use anyhow::Context;
use axum::http::StatusCode;
use axum::response::{AppendHeaders, IntoResponse, Response};
use axum::Json;
use hyper::header::WWW_AUTHENTICATE;
use oidc_core::response_mode::Authorisation;
use oidc_core::response_type::UrlEncodable;
use thiserror::Error;
use tracing::error;

use oidc_core::client::ClientError;
use oidc_core::error::{build_report, OpenIdError, OpenIdErrorType};
use oidc_core::response_mode::encoder::EncodingContext;
use oidc_core::services::authorisation::AuthorisationError;

use crate::routes::authorisation::AuthorisationResponse;

#[derive(Error, Debug)]
#[error(transparent)]
pub struct AuthorisationErrorWrapper(#[from] AuthorisationError);

impl IntoResponse for AuthorisationErrorWrapper {
    fn into_response(self) -> Response {
        error!("Request error: {}", build_report(&self.0));
        match self.0 {
            AuthorisationError::InvalidRedirectUri
            | AuthorisationError::MissingRedirectUri
            | AuthorisationError::InvalidClient(_)
            | AuthorisationError::MissingClient => {
                (StatusCode::BAD_REQUEST, self.0.to_string()).into_response()
            }
            AuthorisationError::InternalError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response()
            }
            AuthorisationError::RedirectableErr {
                err,
                response_mode,
                redirect_uri,
                state,
                provider,
                keystore_service,
                client,
            } => {
                let encoding_context = EncodingContext {
                    client: &client,
                    redirect_uri: &redirect_uri,
                    response_mode,
                    provider: &provider,
                    keystore_service: &keystore_service,
                };
                let mut parameters = err.params();
                if let Some(state) = state {
                    parameters = (parameters, state).params();
                }
                match Authorisation::new(encoding_context, parameters)
                    .context("Error encoding response")
                {
                    Ok(authorisation) => AuthorisationResponse(authorisation).into_response(),
                    Err(auth_err) => AuthorisationErrorWrapper(auth_err.into()).into_response(),
                }
            }
            AuthorisationError::Persistence(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response()
            }
        }
    }
}

#[derive(Error, Debug)]
#[error(transparent)]
pub struct OpenIdErrorResponse(#[from] OpenIdError);

impl IntoResponse for OpenIdErrorResponse {
    fn into_response(self) -> Response {
        let err = self.0;
        error!("Request error: {}", build_report(&err));
        let status_code = if err.error_type() == OpenIdErrorType::InvalidClient {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::BAD_REQUEST
        };
        (status_code, Json(err)).into_response()
    }
}

impl From<ClientError> for OpenIdErrorResponse {
    fn from(err: ClientError) -> Self {
        OpenIdError::server_error(err).into()
    }
}

#[derive(Error, Debug)]
#[error(transparent)]
pub struct WwwAuthenticateErrorResponse(#[from] OpenIdError);

impl IntoResponse for WwwAuthenticateErrorResponse {
    fn into_response(self) -> Response {
        let err = self.0;
        error!("Request error: {}", build_report(&err));
        let status_code = match err.error_type() {
            OpenIdErrorType::InvalidToken => StatusCode::UNAUTHORIZED,
            OpenIdErrorType::InsufficientScope => StatusCode::FORBIDDEN,
            _ => StatusCode::BAD_REQUEST,
        };

        let Ok(error) = serde_urlencoded::to_string(err) else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to encode error").into_response();
        };
        let headers = AppendHeaders([(WWW_AUTHENTICATE, error)]);
        (status_code, headers).into_response()
    }
}
