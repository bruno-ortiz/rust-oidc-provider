use actix_web::{get, web, App, HttpServer, Responder};
use josekit::jwk::alg::ec::EcCurve;
use josekit::jwk::Jwk;

use oidc_types::jose::jwk_set::{JwkHolder, JwkSet};
use oidc_types::scopes;

#[get("/key")]
async fn index() -> impl Responder {
    let mut ec_key = Jwk::generate_ec_key(EcCurve::P256).unwrap();
    ec_key.set_key_id("ec_key_id");
    web::Json(JwkSet::new(vec![ec_key]))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(index))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
