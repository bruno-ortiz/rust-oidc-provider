mod profile;

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::str::FromStr;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, get_service, post, MethodRouter};
use axum::{Extension, Form, Router};
use lazy_static::lazy_static;
use serde::Deserialize;
use tera::{Context, Tera};
use time::OffsetDateTime;
use tower_http::services::ServeDir;

use oidc_admin::oidc_admin::{
    ClientInfoRequest, CompleteLoginRequest, ConfirmConsentRequest, InteractionInfoRequest,
};
use oidc_admin::{GrpcRequest, InteractionClient};
use oidc_core::client::register_client;
use oidc_core::configuration::{OpenIDProviderConfiguration, OpenIDProviderConfigurationBuilder};
use oidc_core::models::client::ClientInformation;
use oidc_server::server::OidcServer;
use oidc_types::acr::Acr;
use oidc_types::auth_method::AuthMethod;
use oidc_types::client::{ClientID, ClientMetadataBuilder};
use oidc_types::grant_type::GrantType;
use oidc_types::jose::jwk_set::JwkSet;
use oidc_types::jose::HS256;
use oidc_types::response_type::ResponseTypeValue;
use oidc_types::response_type::ResponseTypeValue::{IdToken, Token};
use ResponseTypeValue::Code;

lazy_static! {
    pub static ref TEMPLATES: Tera = {
        let mut tera = match Tera::new("example/static/pages/**/*") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };
        tera.autoescape_on(vec![".html", ".sql"]);
        tera
    };
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/interaction/login", get(login_page))
        .route("/interaction/consent", get(consent_page))
        .route("/login", post(login))
        .route("/consent", post(consent))
        .nest("/assets", serve_dir("./example/static/assets"));

    let config = OpenIDProviderConfigurationBuilder::default()
        .issuer("https://766c-2804-431-c7c6-24e4-200c-3f6f-2dfc-553e.sa.ngrok.io")
        .build()
        .expect("Expected valid configuration");

    create_client(
        &config,
        "Test client 1",
        "1d8fca3b-a2f1-48c2-924d-843e5173a951",
        "1fCW^$)*(I#tll2EH#!MfsHFQ$*6&gEx",
    )
    .await;
    create_client(
        &config,
        "Test client 2",
        "e9f6fa6b-4fb2-4a85-85c0-14d13521a377",
        "T*8XnO6JRqI8rrPh^5dUzE0BNQR0u5Hy",
    )
    .await;

    OidcServer::with_configuration(config)
        .with_router(app)
        .run()
        .await
        .unwrap()
}

async fn create_client(config: &OpenIDProviderConfiguration, name: &str, id: &str, secret: &str) {
    let callback_url = "http://localhost:8000/callback"
        .try_into()
        .expect("expect valid url");
    let client_metadata = ClientMetadataBuilder::default()
        .redirect_uris(vec![callback_url])
        .jwks(JwkSet::default())
        .token_endpoint_auth_method(AuthMethod::ClientSecretPost)
        .id_token_signed_response_alg(HS256)
        .client_name(name)
        .response_types(vec![Code, IdToken, Token])
        .grant_types(vec![GrantType::AuthorizationCode, GrantType::RefreshToken])
        .build()
        .expect("Valid client metadata");

    let client = ClientInformation::new(
        ClientID::from_str(id).unwrap(),
        OffsetDateTime::now_utc(),
        secret.to_owned().into(),
        None,
        client_metadata,
    );

    register_client(config, client)
        .await
        .expect("Expected successful client registration");
}

fn serve_dir<P: AsRef<Path>>(path: P) -> MethodRouter {
    get_service(ServeDir::new(path)).handle_error(|error: io::Error| async move {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled internal error: {}", error),
        )
    })
}

async fn login_page(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let mut context: Context = Context::new();
    context.insert("interaction_id", params.get("interaction_id").unwrap());
    Html(TEMPLATES.render("login.html", &context).unwrap())
}

async fn consent_page(
    Query(params): Query<HashMap<String, String>>,
    Extension(mut interaction_client): Extension<InteractionClient>,
) -> Html<String> {
    let mut context: Context = Context::new();
    let interaction_id = params.get("interaction_id").unwrap();

    let request = GrpcRequest::new(InteractionInfoRequest {
        interaction_id: interaction_id.to_owned(),
    });
    let interaction_info = interaction_client
        .get_interaction_info(request)
        .await
        .unwrap()
        .into_inner();

    let auth_request = interaction_info.request.unwrap();
    let request = GrpcRequest::new(ClientInfoRequest {
        client_id: auth_request.client_id,
    });

    let client_info = interaction_client
        .get_client_info(request)
        .await
        .unwrap()
        .into_inner();

    context.insert("interaction_id", interaction_id);
    context.insert("scopes", &auth_request.scopes);
    context.insert("orgName", &client_info.client_name.unwrap());
    Html(TEMPLATES.render("consent.html", &context).unwrap())
}

#[derive(Debug, Clone, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    interaction_id: String,
}

// #[axum_macros::debug_handler]
async fn login(
    Form(req): Form<LoginRequest>,
    Extension(mut interaction_client): Extension<InteractionClient>,
) -> Response {
    if req.username != "xoze" || req.password != "1234" {
        return (StatusCode::UNAUTHORIZED, "Invalid user or password").into_response();
    }

    let request = GrpcRequest::new(CompleteLoginRequest {
        sub: "some-user-id".to_string(),
        interaction_id: req.interaction_id,
        acr: Some(Acr::default().to_string()),
        amr: None,
    });
    let res = interaction_client
        .complete_login(request)
        .await
        .unwrap()
        .into_inner();

    Redirect::to(res.redirect_uri.as_str()).into_response()
}

#[derive(Debug, Clone, Deserialize)]
struct ConsentRequest {
    interaction_id: String,
}

async fn consent(
    Form(req): Form<ConsentRequest>,
    Extension(mut interaction_client): Extension<InteractionClient>,
) -> impl IntoResponse {
    let request = GrpcRequest::new(ConfirmConsentRequest {
        interaction_id: req.interaction_id,
        scopes: vec!["openid".to_owned()],
    });
    let res = interaction_client
        .confirm_consent(request)
        .await
        .unwrap()
        .into_inner();

    Redirect::to(res.redirect_uri.as_str()).into_response()
}
