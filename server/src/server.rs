use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use oidc_admin::{AdminServer, AdminServerError, InteractionServiceClient};
use thiserror::Error;
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::trace::TraceLayer;
use tower_http::ServiceBuilderExt;
use tracing::info;

use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::response_mode::encoder::DynamicResponseModeEncoder;
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;
use oidc_core::services::authorisation::AuthorisationService;

use crate::middleware::SessionManagerLayer;
use crate::routes::authorisation::authorise;
use crate::routes::discovery::{discovery, DISCOVERY_ROUTE};
use crate::routes::jwks::jwks;
use crate::routes::token::token;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("Error running oidc server {}", .0)]
    OpenId(#[from] hyper::Error),
    #[error("Error running admin server {}", .0)]
    Admin(#[from] AdminServerError),
}

#[derive(Default)]
pub struct OidcServer {
    custom_routes: Option<Router>,
}

impl OidcServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_configuration(configuration: OpenIDProviderConfiguration) -> Self {
        OpenIDProviderConfiguration::set(configuration);
        Self {
            custom_routes: None,
        }
    }

    pub fn with_router(self, router: Router) -> Self {
        Self {
            custom_routes: Some(router),
        }
    }

    pub async fn run(self) -> Result<(), ServerError> {
        tokio::spawn(async move {
            let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
            info!("Admin Server listening on {}", addr);
            AdminServer.run(addr).await.map_err(ServerError::Admin)
        });
        let oidc_router = self.oidc_router().await;
        let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
        info!("OpenId Server listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(oidc_router.into_make_service())
            .await
            .map_err(ServerError::OpenId)?;
        // try_join!(oidc_server, admin_server)?;
        println!("joined");
        Ok(())
    }

    async fn oidc_router(&self) -> Router {
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
            .route(routes.token, post(token));
        if let Some(custom_routes) = self.custom_routes.as_ref().cloned() {
            router = router.nest("/", custom_routes);
        }
        let interaction_client = InteractionServiceClient::connect("http://localhost:4000")
            .await
            .expect("expected succesful gRPC connection");
        router.route_layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CookieManagerLayer::new())
                .layer(SessionManagerLayer::signed(&[0; 32])) //TODO: key configuration
                .add_extension(Arc::new(DynamicResponseModeEncoder::from(configuration)))
                .add_extension(authorisation_service)
                .add_extension(configuration)
                .add_extension(interaction_client),
        )
    }
}
