use std::sync::Arc;

use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::response::AppendHeaders;
use axum::Json;
use axum_extra::headers::HeaderName;

use oidc_core::services::token::TokenService;
use oidc_types::token::TokenResponse;
use oidc_types::token_request::TokenRequestBody;

use crate::authenticated_request::AuthenticatedRequest;
use crate::routes::error::OpenIdErrorResponse;

// #[axum_macros::debug_handler]
pub async fn token(
    State(service): State<Arc<TokenService>>,
    request: AuthenticatedRequest<TokenRequestBody>,
) -> axum::response::Result<
    (
        AppendHeaders<[(HeaderName, &'static str); 2]>,
        Json<TokenResponse>,
    ),
    OpenIdErrorResponse,
> {
    let tokens = service
        .execute(request.body, request.authenticated_client)
        .await?;
    let headers = AppendHeaders([(CACHE_CONTROL, "no-store"), (PRAGMA, "no-cache")]);
    Ok((headers, Json(tokens)))
}
