use actix_web::{App, get, HttpServer, Responder, web};

use oidc_types::scopes;

#[get("/scopes")]
async fn index() -> impl Responder {
    format!("Scope:{}", scopes!("test", "user", "xpto"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(index))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}