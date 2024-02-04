use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_types::jose::jwk_set::PublicJwkSet;

pub async fn jwks(State(provider): State<Arc<OpenIDProviderConfiguration>>) -> Json<PublicJwkSet> {
    Json(provider.keystore().public())
}
