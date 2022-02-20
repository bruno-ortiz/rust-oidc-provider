use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, get_service, MethodRouter};
use axum::Router;
use hyper::Body;
use rand::Rng;
use time::Duration;
use tower::{ServiceBuilder, ServiceExt};
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tower_http::services::{ServeDir, ServeFile};

use oidc_axum::extractors::SessionHolder;
use oidc_axum::middleware::SessionManagerLayer;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/login", get(login))
        .layer(
            ServiceBuilder::new()
                .layer(CookieManagerLayer::new())
                .layer(SessionManagerLayer::new()),
        )
        .nest("/assets", serve_dir("./oidc-example/static/assets"));

    // run it
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
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
    let path: PathBuf = "./oidc-example/static/pages/login.html".parse().unwrap();
    ServeFile::new(path)
        .oneshot(request)
        .await
        .unwrap()
        .into_response()
}
