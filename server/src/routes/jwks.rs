use axum::Json;

use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_types::jose::jwk_set::PublicJwkSet;

pub async fn jwks() -> Json<PublicJwkSet> {
    let config = OpenIDProviderConfiguration::instance();
    Json(config.keystore().public())
}
