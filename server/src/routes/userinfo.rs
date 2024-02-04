use std::sync::Arc;

use axum::extract::State;
use axum::response::Result;
use axum::Json;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;

use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::error::OpenIdError;
use oidc_core::models::access_token::AccessToken;
use oidc_core::services::token::TokenService;
use oidc_core::services::userinfo::UserInfoService;
use oidc_types::userinfo::UserInfo;

use crate::routes::error::OpenIdErrorResponse;

// #[axum_macros::debug_handler]
pub async fn userinfo(
    bearer_token: TypedHeader<Authorization<Bearer>>,
    State(provider): State<Arc<OpenIDProviderConfiguration>>,
    State(service): State<Arc<UserInfoService>>,
    State(token_service): State<Arc<TokenService>>,
) -> Result<Json<UserInfo>, OpenIdErrorResponse> {
    //TODO: review error to respond wwwAuthenticate Header
    let token = find_access_token(&provider, bearer_token).await?;
    let active_token = token_service
        .as_active(token)
        .await
        .map_err(OpenIdError::from)?;
    let user_info = service.get_user_info(active_token).await?;
    Ok(Json(user_info))
}

async fn find_access_token(
    provider: &OpenIDProviderConfiguration,
    bearer_token: TypedHeader<Authorization<Bearer>>,
) -> Result<AccessToken, OpenIdError> {
    let token = AccessToken::find(provider, bearer_token.token())
        .await?
        .ok_or_else(|| OpenIdError::invalid_grant("Invalid token"))?;
    Ok(token)
}
