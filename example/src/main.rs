use std::collections::HashMap;
use std::error::Error;
use std::str::FromStr;

use axum::extract::Query;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
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
use oidc_core::models::client::ClientInformation;
use oidc_persistence::adapter::SeaOrmAdapterContainer;
use oidc_persistence::MigrationAction;
use oidc_server::claims::ClaimsSupported;
use oidc_server::provider::{OpenIDProviderConfiguration, OpenIDProviderConfigurationBuilder};
use oidc_server::request_object::RequestObjectConfigurationBuilder;
use oidc_server::server::OidcServer;
use oidc_types::auth_method::AuthMethod;
use oidc_types::client::{ClientID, ClientMetadataBuilder};
use oidc_types::grant_type::GrantType;
use oidc_types::jose::jwk_set::JwkSet;
use oidc_types::jose::jws::SigningAlgorithm;
use oidc_types::jose::{EdDSA, UnsecuredJwsAlgorithm, ES256, PS256, RS256};
use oidc_types::response_type::ResponseTypeValue;
use oidc_types::response_type::ResponseTypeValue::{IdToken, Token};
use oidc_types::scopes;
use oidc_types::secret::PlainTextSecret;
use ResponseTypeValue::Code;

use crate::profile::MockProfileResolver;

mod profile;

lazy_static! {
    pub static ref TEMPLATES: Tera = {
        let mut tera = match Tera::new("example/static/pages/**/*") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                std::process::exit(1);
            }
        };
        tera.autoescape_on(vec![".html", ".sql"]);
        tera
    };
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let adapter =
        SeaOrmAdapterContainer::new("mysql://dev:dev@localhost:3306/oidc-provider").await?;

    adapter.run_migrations(MigrationAction::Fresh).await?;

    let app = Router::new()
        .route("/interaction/login", get(login_page))
        .route("/interaction/consent", get(consent_page))
        .route("/login", post(login))
        .route("/consent", post(consent))
        .nest_service("/assets", ServeDir::new("./example/static/assets"));

    let config = OpenIDProviderConfigurationBuilder::default()
        .issuer("https://e927-189-110-116-171.ngrok-free.app")
        .profile_resolver(MockProfileResolver)
        .claims_supported(ClaimsSupported::all())
        .request_object_signing_alg_values_supported(vec![
            SigningAlgorithm::from(RS256),
            SigningAlgorithm::from(PS256),
            SigningAlgorithm::from(ES256),
            SigningAlgorithm::from(EdDSA),
            SigningAlgorithm::from(UnsecuredJwsAlgorithm::None),
        ])
        .request_object(
            RequestObjectConfigurationBuilder::default()
                .request(true)
                .build()?,
        )
        .claims_parameter_supported(true)
        .with_adapter(Box::new(adapter))
        .build()
        .expect("Expected valid configuration");

    create_client(
        &config,
        "Test client 1",
        "1d8fca3b-a2f1-48c2-924d-843e5173a951",
        "1fCW^$)*(I#tll2EH#!MfsHFQ$*6&gEx",
        AuthMethod::ClientSecretBasic,
    )
    .await;
    create_client(
        &config,
        "Test client 2",
        "e9f6fa6b-4fb2-4a85-85c0-14d13521a377",
        "T*8XnO6JRqI8rrPh^5dUzE0BNQR0u5Hy",
        AuthMethod::ClientSecretBasic,
    )
    .await;

    create_client(
        &config,
        "Test Client_Secret_Post",
        "e9f6fa6b-4fb2-4a85-85c0-14d13521a378",
        "T*8XnO6JRqI8rrPh^5dUzE0BNQR0u5Hy",
        AuthMethod::ClientSecretPost,
    )
    .await;

    OidcServer::new(config).with_router(app).run().await?;
    Ok(())
}

async fn create_client(
    config: &OpenIDProviderConfiguration,
    name: &str,
    id: &str,
    secret: &str,
    auth_method: AuthMethod,
) {
    let callback_url = "https://www.certification.openid.net/test/a/rust-oidc-test/callback"
        .try_into()
        .expect("expect valid url");
    let client_metadata = ClientMetadataBuilder::default()
        .redirect_uris(vec![callback_url])
        .jwks(JwkSet::default())
        .token_endpoint_auth_method(auth_method)
        .id_token_signed_response_alg(ES256)
        .client_name(name)
        .response_types(vec![Code, IdToken, Token])
        .grant_types(vec![GrantType::AuthorizationCode, GrantType::RefreshToken])
        .scope(scopes!("openid", "profile", "email", "phone", "address"))
        .build()
        .expect("Valid client metadata");

    let client = ClientInformation::new(
        ClientID::from_str(id).unwrap(),
        OffsetDateTime::now_utc(),
        Some(PlainTextSecret::from(secret.to_owned())),
        None,
        client_metadata,
    );

    register_client(config, client)
        .await
        .expect("Expected successful client registration");
}

async fn login_page(
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
    let login_hint = auth_request.login_hint.unwrap_or_default();
    context.insert("interaction_id", interaction_id);
    context.insert("login_hint", &login_hint);
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
    Extension(mut interaction_client): Extension<InteractionClient>,
    Form(req): Form<LoginRequest>,
) -> Response {
    // if req.username != "xoze" || req.password != "1234" {
    //     return (StatusCode::UNAUTHORIZED, "Invalid user or password").into_response();
    // }

    let interaction_info = interaction_client
        .get_interaction_info(GrpcRequest::new(InteractionInfoRequest {
            interaction_id: req.interaction_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    let auth_request = interaction_info
        .request
        .expect("Should have an auth request");
    let request = GrpcRequest::new(CompleteLoginRequest {
        sub: "some-user-id".to_string(),
        interaction_id: req.interaction_id,
        acr: auth_request.requested_acr.last().cloned(),
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
    Extension(mut interaction_client): Extension<InteractionClient>,
    Form(req): Form<ConsentRequest>,
) -> impl IntoResponse {
    let interaction_id = req.interaction_id;
    let request = GrpcRequest::new(InteractionInfoRequest {
        interaction_id: interaction_id.to_owned(),
    });
    let interaction_info = interaction_client
        .get_interaction_info(request)
        .await
        .unwrap()
        .into_inner();
    let request = GrpcRequest::new(ConfirmConsentRequest {
        interaction_id,
        scopes: interaction_info.request.unwrap().scopes,
    });
    let res = interaction_client
        .confirm_consent(request)
        .await
        .unwrap()
        .into_inner();

    Redirect::to(res.redirect_uri.as_str()).into_response()
}
