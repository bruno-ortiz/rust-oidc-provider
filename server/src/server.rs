use std::borrow::Borrow;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use futures::try_join;
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::trace::TraceLayer;
use tower_http::ServiceBuilderExt;
use tracing::info;

use oidc_core::client::ClientService;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::response_mode::encoder::DynamicResponseModeEncoder;
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;
use oidc_core::services::authorisation::AuthorisationService;
use oidc_core::services::interaction::InteractionService;

use crate::middleware::SessionManagerLayer;
use crate::routes::authorisation::authorise;

#[derive(Default)]
pub struct OidcServer {
    custom_routes: Option<Router>,
    configuration: Arc<OpenIDProviderConfiguration>,
}

impl OidcServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_configuration(configuration: OpenIDProviderConfiguration) -> Self {
        Self {
            configuration: Arc::new(configuration),
            custom_routes: None,
        }
    }

    pub fn with_router(self, router: Router) -> Self {
        Self {
            configuration: self.configuration,
            custom_routes: Some(router),
        }
    }

    pub async fn run(self) -> hyper::Result<()> {
        let oidc_router = self.oidc_router();
        // run it
        let oidc_server = async {
            let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
            info!("OpenId Server listening on {}", addr);
            axum::Server::bind(&addr)
                .serve(oidc_router.into_make_service())
                .await
        };

        let admin_server = async {
            let admin_router = Router::new().route("/admin", get(admin));
            let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
            info!("Admin Server listening on {}", addr);
            axum::Server::bind(&addr)
                .serve(admin_router.into_make_service())
                .await
        };

        try_join!(oidc_server, admin_server)?;
        Ok(())
    }

    fn oidc_router(&self) -> Router {
        let routes = self.configuration.routes();
        let adapter = self.configuration.adapters();
        let client_service = Arc::new(ClientService::new(adapter.client()));
        let encoder = Arc::new(DynamicResponseModeEncoder::from(
            self.configuration.borrow(),
        ));
        let authorisation_service = Arc::new(AuthorisationService::new(
            DynamicResponseTypeResolver::from(self.configuration.borrow()),
            encoder.clone(),
            self.configuration.clone(),
        ));
        let interaction_service = Arc::new(InteractionService::new(
            self.configuration.clone(),
            authorisation_service.clone(),
        ));
        // .route("interaction/login", post(login_complete))
        let mut router = Router::new().route(
            routes.authorisation.as_str(),
            get(authorise::<DynamicResponseTypeResolver, Arc<DynamicResponseModeEncoder>>),
        );
        if let Some(custom_routes) = self.custom_routes.as_ref().cloned() {
            router = router.nest("/", custom_routes);
        }
        router.layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CookieManagerLayer::new())
                .layer(SessionManagerLayer::signed(&[0; 32])) //TODO: key configuration
                .add_extension(client_service)
                .add_extension(interaction_service)
                .add_extension(encoder)
                .add_extension(authorisation_service)
                .add_extension(self.configuration.clone()),
        )
    }
}

async fn admin() -> &'static str {
    "test"
}
