use axum::{Extension, Json};
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_types::jose::jwk_set::JwkSet;
use std::sync::Arc;

pub async fn jwks(Extension(config): Extension<Arc<OpenIDProviderConfiguration>>) -> Json<JwkSet> {
    Json(config.jwks().clone())
}
