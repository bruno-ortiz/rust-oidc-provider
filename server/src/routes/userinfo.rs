use axum::response::Result;
use axum::Json;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;

use oidc_core::error::OpenIdError;
use oidc_core::models::access_token::AccessToken;
use oidc_core::userinfo::get_user_info;
use oidc_types::userinfo::UserInfo;

use crate::routes::error::OpenIdErrorResponse;

// #[axum_macros::debug_handler]
pub async fn userinfo(
    bearer_token: TypedHeader<Authorization<Bearer>>,
) -> Result<Json<UserInfo>, OpenIdErrorResponse> {
    //TODO: review error to respond wwwAuthenticate Header
    let token = find_access_token(bearer_token).await?;
    let active_token = token.into_active().await.map_err(OpenIdError::from)?;
    let user_info = get_user_info(active_token).await?;
    Ok(Json(user_info))
}

async fn find_access_token(
    bearer_token: TypedHeader<Authorization<Bearer>>,
) -> Result<AccessToken, OpenIdError> {
    let token = AccessToken::find(bearer_token.token())
        .await?
        .ok_or_else(|| OpenIdError::invalid_grant("Invalid token"))?;
    Ok(token)
}
