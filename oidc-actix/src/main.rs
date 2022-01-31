use actix_session::CookieSession;
use actix_web::{App, HttpServer};

use oidc_actix::oidc_configuration;
use oidc_core::configuration::OpenIDProviderConfiguration;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let config = OpenIDProviderConfiguration::default();
        App::new()
            .wrap(CookieSession::private(&[0; 32]).secure(false))
            .configure(oidc_configuration(config))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
