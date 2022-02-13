use std::path::PathBuf;

use actix_files::{Files, NamedFile};
use actix_session::CookieSession;
use actix_web::{middleware, web, App, HttpServer, Result};

use oidc_actix::oidc_configuration;
use oidc_actix::server::CustomServer;
use oidc_core::configuration::OpenIDProviderConfiguration;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    CustomServer::new()
        .wrap(middleware::Logger::default())
        .wrap(CookieSession::signed(&[0; 32]).secure(false))
        .with_configuration(|cfg| {
            cfg.route("/custom/route", web::get().to(login));
        })
        .run()
        .await?;

    HttpServer::new(|| {
        let config = OpenIDProviderConfiguration::new("http://localhost:8080");
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
            .service(Files::new("/assets", "./oidc-example/static/assets"))
            .configure(oidc_configuration(config))
            .route("/login", web::get().to(login))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

async fn login() -> Result<NamedFile> {
    let path: PathBuf = "./oidc-example/static/pages/login.html".parse().unwrap();
    Ok(NamedFile::open(path)?)
}
