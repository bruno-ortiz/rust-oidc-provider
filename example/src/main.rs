use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, get_service, MethodRouter};
use axum::Router;
use hyper::Body;
use oidc_core::client::register_client;
use oidc_core::configuration::OpenIDProviderConfigurationBuilder;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

use oidc_server::extractors::SessionHolder;
use oidc_server::server::OidcServer;
use oidc_types::auth_method::AuthMethod;
use oidc_types::client::{ClientID, ClientInformation, ClientMetadataBuilder};
use oidc_types::jose::jwk_set::JwkSet;
use oidc_types::response_type::ResponseTypeValue;
use oidc_types::response_type::ResponseTypeValue::{IdToken, Token};
use ResponseTypeValue::Code;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/interaction/login", get(login))
        .nest("/assets", serve_dir("./example/static/assets"));

    let config = OpenIDProviderConfigurationBuilder::default()
        .issuer("http://localhost:3000")
        .build()
        .expect("Expected valid configuration");

    let callback_url = "http://localhost:8000/callback"
        .try_into()
        .expect("expect valid url");
    let client_metadata = ClientMetadataBuilder::default()
        .redirect_uris(vec![callback_url])
        .jwks(JwkSet::default())
        .token_endpoint_auth_method(AuthMethod::PrivateKeyJwt)
        .client_name("Test client")
        .response_types(vec![Code, IdToken, Token])
        .build()
        .expect("Valid client metadata");

    let client = ClientInformation {
        id: ClientID::from_str("1d8fca3b-a2f1-48c2-924d-843e5173a951").unwrap(),
        metadata: client_metadata,
        issue_date: OffsetDateTime::now_utc(),
    };

    register_client(&config, client)
        .await
        .expect("Expected successful client registration");

    OidcServer::with_configuration(config)
        .with_router(app)
        .run()
        .await
        .unwrap()
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
