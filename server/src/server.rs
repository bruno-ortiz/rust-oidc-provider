use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::{io, signal};
use tracing::info;

use oidc_admin::{AdminServer, AdminServerError};
use oidc_core::configuration::OpenIDProviderConfiguration;

use crate::routes::oidc_router;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("Error running admin server {}", .0)]
    Admin(#[from] AdminServerError),
    #[error("Error running oidc server {}", .0)]
    Io(#[from] io::Error),
}

#[derive(Default)]
pub struct OidcServer {
    custom_routes: Option<Router>,
    provider: OpenIDProviderConfiguration,
}

impl OidcServer {
    pub fn new(provider: OpenIDProviderConfiguration) -> Self {
        Self {
            provider,
            custom_routes: None,
        }
    }

    pub fn with_router(self, router: Router) -> Self {
        Self {
            custom_routes: Some(router),
            provider: self.provider,
        }
    }

    pub async fn run(self) -> Result<(), ServerError> {
        let provider = Arc::new(self.provider);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let addr = SocketAddr::from(([0, 0, 0, 0], 4000));
        let server_ready = AdminServer.run(addr, provider.clone(), async {
            rx.await.ok();
        });
        server_ready.await.expect("Admin server should be ready");
        let router = oidc_router(self.custom_routes, provider).await;
        let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
        let tcp_listener = TcpListener::bind(addr).await?;
        info!("OpenId Server listening on {}", addr);

        axum::serve(tcp_listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        let _ = tx.send(());
        Ok(())
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            // configuration.close_connections().await.expect("Error closing connections")
        },
        _ = terminate => {
            // configuration.close_connections().await.expect("Error closing connections")
        },
    }
}
