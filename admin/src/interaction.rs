use crate::oidc_admin::interaction_service_server::InteractionService;
use crate::oidc_admin::{CompleteLoginReply, CompleteLoginRequest};
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::services::interaction::{complete_login, InteractionError};
use oidc_types::subject::Subject;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

#[derive(Default)]
pub struct InteractionServiceImpl {
    configuration: Arc<OpenIDProviderConfiguration>,
}

impl InteractionServiceImpl {
    pub fn new(configuration: Arc<OpenIDProviderConfiguration>) -> Self {
        Self { configuration }
    }
}

#[tonic::async_trait]
impl InteractionService for InteractionServiceImpl {
    async fn complete_login(
        &self,
        request: Request<CompleteLoginRequest>,
    ) -> Result<Response<CompleteLoginReply>, Status> {
        let c_request = request.into_inner();
        let interaction_id = Uuid::try_parse(c_request.interaction_id.as_str()).map_err(|err| {
            Status::invalid_argument(format!("Failed to parse interaction id. {err}"))
        })?;
        let redirect_uri = complete_login(
            &self.configuration,
            interaction_id,
            Subject::new(c_request.sub),
        )
        .await
        .map_err(|err| match err {
            InteractionError::FailedPreCondition(_) => Status::failed_precondition(err.to_string()),
            InteractionError::NotFound(_) => Status::not_found(err.to_string()),
            InteractionError::Internal(_) => Status::internal(err.to_string()),
        })?;
        Ok(Response::new(CompleteLoginReply {
            redirect_uri: redirect_uri.to_string(),
        }))
    }
}
