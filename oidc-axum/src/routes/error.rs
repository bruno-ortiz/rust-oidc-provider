use thiserror::Error;

use oidc_core::services::authorisation::AuthorisationError;

#[derive(Error, Debug)]
#[error(transparent)]
pub struct AuthorisationErrorWrapper(#[from] AuthorisationError);

// impl ResponseError for AuthorisationErrorWrapper {
//     fn status_code(&self) -> StatusCode {
//         match self.0 {
//             AuthorisationError::InvalidRedirectUri => StatusCode::BAD_REQUEST,
//             AuthorisationError::InvalidClient => StatusCode::BAD_REQUEST,
//             AuthorisationError::MissingClient => StatusCode::BAD_REQUEST,
//             AuthorisationError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
//             AuthorisationError::InteractionErr(_) => StatusCode::INTERNAL_SERVER_ERROR,
//         }
//     }
// }
