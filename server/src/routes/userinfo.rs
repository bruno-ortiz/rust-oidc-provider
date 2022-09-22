use axum::headers::authorization::Bearer;
use std::collections::HashMap;

use axum::headers::Authorization;
use axum::response::Result;
use axum::{Json, TypedHeader};
use oidc_types::userinfo::UserInfo;

use crate::routes::error::OpenIdErrorResponse;

// #[axum_macros::debug_handler]
pub async fn userinfo(
    bearer_token: TypedHeader<Authorization<Bearer>>,
) -> Result<Json<UserInfo>, OpenIdErrorResponse> {
    let token = bearer_token.token();
    Ok(Json(UserInfo::Normal(HashMap::new())))
}
