use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::trace::TraceLayer;
use tower_http::ServiceBuilderExt;

use oidc_core::configuration::OpenIDProviderConfiguration;

use crate::middleware::SessionManagerLayer;
use crate::routes::authorisation::authorise;
use crate::routes::discovery::{discovery, DISCOVERY_ROUTE};
use crate::routes::introspect::introspect;
use crate::routes::jwks::jwks;
use crate::routes::token::token;
use crate::routes::userinfo::userinfo;
use crate::state::AppState;

pub(crate) mod authorisation;
pub(crate) mod discovery;
pub(crate) mod error;
pub(crate) mod introspect;
pub(crate) mod jwks;
pub(crate) mod token;
pub(crate) mod userinfo;

pub(crate) fn oidc_router(
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
        .route(routes.introspect, post(introspect))
        .with_state::<()>(AppState::new(provider.clone()));
    if let Some(custom_routes) = custom_routes {
        router = router.nest("/", custom_routes);
    }
    router.route_layer(
        ServiceBuilder::new()
            .add_extension(provider.clone())
            .layer(TraceLayer::new_for_http())
            .layer(CookieManagerLayer::new())
            .layer(SessionManagerLayer::signed(&provider.session_signing_key())),
    )
}
