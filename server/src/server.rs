use std::env;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use futures::Future;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::{io, signal};
use tower_http::add_extension::AddExtensionLayer;
use tracing::info;

use oidc_admin::{AdminServer, AdminServerError, InteractionServiceClient};
use oidc_core::configuration::OpenIDProviderConfiguration;

use crate::routes::oidc_router;
use crate::socket_addr;

const LOCAL_CLIENT: &str = "http://localhost:4000";

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("Error running admin server {}", .0)]
    Admin(#[from] AdminServerError),
    #[error("Error running oidc server {}", .0)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
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
        self.run_with_signal(shutdown_signal()).await
    }

    pub async fn run_with_signal<F>(self, signal: F) -> Result<(), ServerError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let provider = Arc::new(self.provider);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let adm_ip = env::var("ADMIN_SERVER_IP").unwrap_or("127.0.0.1".to_string());
        let adm_port = env::var("ADMIN_SERVER_PORT").unwrap_or("4000".to_string());
        let server_ready =
            AdminServer.run(socket_addr(&adm_ip, &adm_port)?, provider.clone(), async {
                rx.await.ok();
            });
        server_ready.await.context("Admin server should be ready")?;

        let server_ip = env::var("SERVER_IP").unwrap_or("127.0.0.1".to_string());
        let server_port = env::var("PORT").unwrap_or("3000".to_string());
        let addr = socket_addr(&server_ip, &server_port)?;
        let tcp_listener = TcpListener::bind(addr).await?;

        let interaction_client = InteractionServiceClient::connect(LOCAL_CLIENT)
            .await
            .context("expected successful gRPC connection")?;

        let router = oidc_router(self.custom_routes, provider)
            .layer(AddExtensionLayer::new(interaction_client));

        info!("OpenId Server listening on {}", addr);
        axum::serve(tcp_listener, router)
            .with_graceful_shutdown(signal)
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
