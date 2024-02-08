use std::sync::Arc;

use async_trait::async_trait;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_macros::FromRef;
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::trace::TraceLayer;
use tower_http::ServiceBuilderExt;

use oidc_admin::InteractionServiceClient;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::manager::access_token_manager::AccessTokenManager;
use oidc_core::manager::auth_code_manager::AuthorisationCodeManager;
use oidc_core::manager::grant_manager::GrantManager;
use oidc_core::manager::refresh_token_manager::RefreshTokenManager;
use oidc_core::request_object::RequestObjectProcessor;
use oidc_core::response_mode::encoder::{AuthorisationResponse, DynamicResponseModeEncoder};
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;
use oidc_core::services::authorisation::AuthorisationService;
use oidc_core::services::interaction::InteractionService;
use oidc_core::services::keystore::KeystoreService;
use oidc_core::services::prompt::PromptService;
use oidc_core::services::token::TokenService;
use oidc_core::services::userinfo::UserInfoService;

use crate::middleware::SessionManagerLayer;
use crate::routes::authorisation::authorise;
use crate::routes::discovery::{discovery, DISCOVERY_ROUTE};
use crate::routes::jwks::jwks;
use crate::routes::token::token;
use crate::routes::userinfo::userinfo;

pub(crate) mod authorisation;
pub(crate) mod discovery;
mod error;
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

#[async_trait]
trait RouterExt {
    async fn apply_extensions(self, provider: Arc<OpenIDProviderConfiguration>) -> Router;
}

#[derive(Clone, FromRef)]
pub(crate) struct AppState {
    provider: Arc<OpenIDProviderConfiguration>,
    authorisation_service:
        Arc<AuthorisationService<DynamicResponseTypeResolver, DynamicResponseModeEncoder>>,
    interaction_service: Arc<InteractionService>,
    token_service: Arc<TokenService>,
    userinfo_service: Arc<UserInfoService>,
    request_object_processor: Arc<RequestObjectProcessor>,
    keystore_service: Arc<KeystoreService>,
    encoder: DynamicResponseModeEncoder,
}

impl AppState {
    pub fn new(provider: Arc<OpenIDProviderConfiguration>) -> Self {
        let keystore_service = Arc::new(KeystoreService::new(provider.clone()));
        let grant_manager = Arc::new(GrantManager::new(provider.clone()));
        let at_manager = Arc::new(AccessTokenManager::new(provider.clone()));
        let rt_manager = Arc::new(RefreshTokenManager::new(provider.clone()));
        let ac_manager = Arc::new(AuthorisationCodeManager::new(provider.clone()));
        let prompt_service = Arc::new(PromptService::new(
            provider.clone(),
            keystore_service.clone(),
        ));
        let interaction_service = Arc::new(InteractionService::new(
            provider.clone(),
            prompt_service.clone(),
        ));
        let authorisation_service = Arc::new(AuthorisationService::new(
            DynamicResponseTypeResolver::from(provider.as_ref()),
            DynamicResponseModeEncoder,
            provider.clone(),
            interaction_service.clone(),
            grant_manager.clone(),
            keystore_service.clone(),
        ));
        let token_service = Arc::new(TokenService::new(
            provider.clone(),
            grant_manager.clone(),
            at_manager.clone(),
            rt_manager.clone(),
            ac_manager.clone(),
            keystore_service.clone(),
        ));
        let userinfo_service = Arc::new(UserInfoService::new(
            provider.clone(),
            keystore_service.clone(),
        ));
        let request_object_processor = Arc::new(RequestObjectProcessor::new(
            provider.clone(),
            keystore_service.clone(),
        ));
        Self {
            provider,
            authorisation_service,
            interaction_service,
            token_service,
            userinfo_service,
            request_object_processor,
            keystore_service,
            encoder: DynamicResponseModeEncoder,
        }
    }
}
pub(crate) fn respond(response: AuthorisationResponse) -> Response {
    match response {
        AuthorisationResponse::Redirect(url) => Redirect::to(url.as_str()).into_response(),
        AuthorisationResponse::FormPost(_, _) => todo!(),
    }
}
