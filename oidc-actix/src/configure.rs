use actix_web::web::ServiceConfig;

use oidc_core::configuration::OpenIDProviderConfiguration;

pub fn oidc_configuration(config: OpenIDProviderConfiguration) -> impl FnOnce(&mut ServiceConfig) {
    |cfg: &mut ServiceConfig| {}
}
