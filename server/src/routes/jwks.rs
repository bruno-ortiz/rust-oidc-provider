use axum::Json;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_types::jose::jwk_set::JwkSet;

pub async fn jwks() -> Json<JwkSet> {
    let config = OpenIDProviderConfiguration::instance();
    Json(config.keystore().inner().clone())
}
