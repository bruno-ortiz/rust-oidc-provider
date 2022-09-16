use crate::interaction::InteractionServiceImpl;
pub use crate::oidc_admin::interaction_service_client::InteractionServiceClient;
use crate::oidc_admin::interaction_service_server::InteractionServiceServer;
use std::net::SocketAddr;
use thiserror::Error;
use tonic::transport::{Error as TonicError, Server};
pub use tonic::Request as GrpcRequest;

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
    pub async fn run(self, addr: SocketAddr) -> Result<(), AdminServerError> {
        let service = InteractionServiceImpl::new();

        Server::builder()
            .add_service(InteractionServiceServer::new(service))
            .serve(addr)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {}
