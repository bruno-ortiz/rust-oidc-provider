use std::io;
use std::path::{Path, PathBuf};

use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, get_service, MethodRouter};
use axum::Router;
use hyper::Body;
use time::Duration;
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

use oidc_server::extractors::SessionHolder;
use oidc_server::server::OidcServer;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/login", get(login))
        .nest("/assets", serve_dir("./oidc-example/static/assets"));

    OidcServer::new().with_router(app).run().await.unwrap()
}

fn serve_dir<P: AsRef<Path>>(path: P) -> MethodRouter {
    get_service(ServeDir::new(path)).handle_error(|error: io::Error| async move {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled internal error: {}", error),
        )
    })
}

async fn login(session: SessionHolder, request: Request<Body>) -> Response {
    println!("session:{:?}", session);

    session.set_duration(Duration::seconds(90));
    let path: PathBuf = "./example/static/pages/login.html".parse().unwrap();
    ServeFile::new(path)
        .oneshot(request)
        .await
        .unwrap()
        .into_response()
}
