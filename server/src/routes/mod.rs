use std::sync::Arc;

use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::trace::TraceLayer;
use tower_http::ServiceBuilderExt;

use oidc_admin::InteractionServiceClient;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::response_mode::encoder::AuthorisationResponse;

use crate::middleware::SessionManagerLayer;
use crate::routes::authorisation::authorise;
use crate::routes::discovery::{discovery, DISCOVERY_ROUTE};
use crate::routes::jwks::jwks;
use crate::routes::token::token;
use crate::routes::userinfo::userinfo;
use crate::state::AppState;

pub(crate) mod authorisation;
pub(crate) mod discovery;
pub(crate) mod error;
pub(crate) mod jwks;
pub(crate) mod token;
pub(crate) mod userinfo;

const LOCAL_CLIENT: &str = "http://localhost:4000";

pub(crate) async fn oidc_router(
    custom_routes: Option<Router>,
    provider: Arc<OpenIDProviderConfiguration>,
) -> Router {
    let routes = provider.routes();
    let mut router = Router::new()
        .route(DISCOVERY_ROUTE, get(discovery))
        .route(routes.authorisation, get(authorise))
        .route(routes.jwks, get(jwks))
        .route(routes.token, post(token))
        .route(routes.userinfo, get(userinfo).post(userinfo))
        .with_state::<()>(AppState::new(provider.clone()));
    if let Some(custom_routes) = custom_routes {
        router = router.nest("/", custom_routes);
    }
    let interaction_client = InteractionServiceClient::connect(LOCAL_CLIENT)
        .await
        .expect("expected successful gRPC connection");
    router.route_layer(
        ServiceBuilder::new()
            .add_extension(interaction_client)
            .add_extension(provider.clone())
            .layer(TraceLayer::new_for_http())
            .layer(CookieManagerLayer::new())
            .layer(SessionManagerLayer::signed(&[0; 32])), //TODO: key configuration
    )
}

pub(crate) fn respond(response: AuthorisationResponse) -> Response {
    match response {
        AuthorisationResponse::Redirect(url) => Redirect::to(url.as_str()).into_response(),
        AuthorisationResponse::FormPost(_, _) => todo!(),
    }
}
