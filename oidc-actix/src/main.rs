use actix_web::{App, get, HttpServer, Responder, web};
use josekit::jwk::alg::ec::EcCurve;
use josekit::jwk::Jwk;

use oidc_actix::oidc_configuration;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_types::jose::jwk_set::JwkSet;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let config = OpenIDProviderConfiguration::default();
        App::new().configure(oidc_configuration(config))
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
