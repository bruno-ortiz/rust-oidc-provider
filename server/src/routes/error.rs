use axum::body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

use oidc_core::services::authorisation::AuthorisationError;

#[derive(Error, Debug)]
#[error(transparent)]
pub struct AuthorisationErrorWrapper(#[from] AuthorisationError);

impl IntoResponse for AuthorisationErrorWrapper {
    fn into_response(self) -> Response {
        let body = body::boxed(body::Full::from(self.0.to_string()));

        match self.0 {
            AuthorisationError::InvalidRedirectUri
            | AuthorisationError::InvalidClient(_)
            | AuthorisationError::MissingClient => Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body)
                .unwrap(),
            AuthorisationError::InternalError(_) | AuthorisationError::InteractionErr(_) => {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(body)
                    .unwrap()
            }
        }
    }
}
