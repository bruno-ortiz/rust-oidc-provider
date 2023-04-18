use std::net::SocketAddr;

use axum::Router;
use thiserror::Error;
use tracing::info;

use crate::routes::oidc_router;
use oidc_admin::{AdminServer, AdminServerError};
use oidc_core::configuration::OpenIDProviderConfiguration;

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
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
        let server_ready = AdminServer.run(addr, async {
            rx.await.ok();
        });
        server_ready.await.expect("Admin server should be ready");
        let oidc_router = oidc_router(self.custom_routes).await;
        let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
        info!("OpenId Server listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(oidc_router.into_make_service())
            .await
            .map_err(ServerError::OpenId)?;
        let _ = tx.send(());
        Ok(())
    }
}
