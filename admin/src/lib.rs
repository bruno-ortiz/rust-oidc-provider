use std::future::Future;
use std::net::SocketAddr;

use thiserror::Error;
use tokio::sync::oneshot::Receiver;
use tonic::transport::{Error as TonicError, Server};
pub use tonic::Request as GrpcRequest;
use tracing::info;

use crate::interaction::InteractionServiceImpl;
pub use crate::oidc_admin::interaction_service_client::InteractionServiceClient;
use crate::oidc_admin::interaction_service_server::InteractionServiceServer;

pub mod interaction;

pub mod oidc_admin {
    tonic::include_proto!("oidc.admin");
}

pub type InteractionClient = InteractionServiceClient<tonic::transport::Channel>;

#[derive(Debug, Error)]
#[error("Error running admin server: {}", .0)]
pub struct AdminServerError(#[from] TonicError);

pub struct AdminServer;

impl AdminServer {
    pub fn run<F: Future<Output = ()> + Send + 'static>(
        self,
        addr: SocketAddr,
        signal: F,
    ) -> Receiver<()> {
        let (callback, server_ready) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let service = InteractionServiceImpl::new();
            Server::builder()
                .add_service(InteractionServiceServer::new(service))
                .serve_with_shutdown(addr, async move {
                    info!("Admin Server listening on {}", addr);
                    let _ = callback.send(()); //server is ready
                    signal.await;
                })
                .await
        });
        server_ready
    }
}

#[cfg(test)]
mod tests {}
