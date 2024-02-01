use axum::{Extension, Json};
use std::sync::Arc;

use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_types::jose::jwk_set::PublicJwkSet;

pub async fn jwks(
    Extension(provider): Extension<Arc<OpenIDProviderConfiguration>>,
) -> Json<PublicJwkSet> {
    Json(provider.keystore().public())
}
