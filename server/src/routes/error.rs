use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;
use tracing::error;

use oidc_core::error::{OpenIdError, OpenIdErrorType};
use oidc_core::services::authorisation::AuthorisationError;

#[derive(Error, Debug)]
#[error(transparent)]
pub struct AuthorisationErrorWrapper(#[from] AuthorisationError);

impl IntoResponse for AuthorisationErrorWrapper {
    fn into_response(self) -> Response {
        error!("Request error, {:?}", self.0);
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
            AuthorisationError::RedirectableErr { .. } => {
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
        error!("Request error, {:?}", err);
        let status_code = if err.error_type() == OpenIdErrorType::InvalidClient {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::BAD_REQUEST
        };
        (status_code, Json(err)).into_response()
    }
}
