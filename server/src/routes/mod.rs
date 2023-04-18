use crate::middleware::SessionManagerLayer;
use crate::routes::authorisation::authorise;
use crate::routes::discovery::{discovery, DISCOVERY_ROUTE};
use crate::routes::jwks::jwks;
use crate::routes::token::token;
use crate::routes::userinfo::userinfo;
use axum::routing::{get, post};
use axum::Router;
use oidc_admin::InteractionServiceClient;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::response_mode::encoder::DynamicResponseModeEncoder;
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;
use oidc_core::services::authorisation::AuthorisationService;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::trace::TraceLayer;
use tower_http::ServiceBuilderExt;

pub(crate) mod authorisation;
pub(crate) mod discovery;
mod error;
pub(crate) mod jwks;
pub(crate) mod token;
pub(crate) mod userinfo;

const LOCAL_CLIENT: &str = "http://localhost:4000";

pub(crate) async fn oidc_router(custom_routes: Option<Router>) -> Router {
    let configuration = OpenIDProviderConfiguration::instance();
    let routes = configuration.routes();
    let authorisation_service = Arc::new(AuthorisationService::new(
        DynamicResponseTypeResolver::from(configuration),
        DynamicResponseModeEncoder::from(configuration),
    ));
    let mut router = Router::new()
        .route(DISCOVERY_ROUTE, get(discovery))
        .route(
            routes.authorisation,
            get(authorise::<DynamicResponseTypeResolver, DynamicResponseModeEncoder>),
        )
        .route(routes.jwks, get(jwks))
        .route(routes.token, post(token))
        .route(routes.userinfo, get(userinfo).post(userinfo));
    if let Some(custom_routes) = custom_routes.as_ref().cloned() {
        router = router.nest("/", custom_routes);
    }
    let interaction_client = InteractionServiceClient::connect(LOCAL_CLIENT)
        .await
        .expect("expected successful gRPC connection");
    router.route_layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(CookieManagerLayer::new())
            .layer(SessionManagerLayer::signed(&[0; 32])) //TODO: key configuration
            .add_extension(Arc::new(DynamicResponseModeEncoder::from(configuration)))
            .add_extension(authorisation_service)
            .add_extension(interaction_client),
    )
}
