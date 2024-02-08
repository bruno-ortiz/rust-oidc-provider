use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;
use tracing::error;

use oidc_core::client::ClientError;
use oidc_core::error::{OpenIdError, OpenIdErrorType};
use oidc_core::response_mode::encoder::{
    encode_response, DynamicResponseModeEncoder, EncodingContext,
};
use oidc_core::services::authorisation::AuthorisationError;

use crate::routes::respond;

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
                match encode_response(encoding_context, &DynamicResponseModeEncoder, err, state) {
                    Ok(response) => respond(response),
                    Err(auth_err) => AuthorisationErrorWrapper(auth_err).into_response(),
                }
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

impl From<ClientError> for OpenIdErrorResponse {
    fn from(err: ClientError) -> Self {
        OpenIdError::server_error(err).into()
    }
}
