use std::str::FromStr;
use std::sync::Arc;

use tonic::{Request, Response, Status};
use uuid::Uuid;

use oidc_core::adapter::PersistenceError;
use oidc_core::authorisation_request::ValidatedAuthorisationRequest;
use oidc_core::client::{retrieve_client_info, ClientError};
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::manager::grant_manager::GrantManager;
use oidc_core::manager::interaction_manager::InteractionManager;
use oidc_core::models::client::ClientInformation;
use oidc_core::response_mode::encoder::DynamicResponseModeEncoder;
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;
use oidc_core::services::authorisation::AuthorisationService;
use oidc_core::services::interaction::InteractionError;
use oidc_core::services::interaction::InteractionService as CoreInteractionService;
use oidc_core::services::keystore::KeystoreService;
use oidc_core::services::prompt::PromptService;
use oidc_core::services::types::Interaction;
use oidc_core::user::AuthenticatedUser;
use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::client::ClientID;
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;

use crate::oidc_admin::interaction_info_reply::InteractionType;
use crate::oidc_admin::interaction_service_server::InteractionService;
use crate::oidc_admin::{
    AuthenticatedUserInfo, AuthorisationRequestInfo, ClientInfo, ClientInfoRequest,
    CompleteLoginReply, CompleteLoginRequest, ConfirmConsentReply, ConfirmConsentRequest,
    InteractionInfoReply, InteractionInfoRequest,
};

pub struct InteractionServiceImpl {
    authorisation_service:
        AuthorisationService<DynamicResponseTypeResolver, DynamicResponseModeEncoder>,
    provider: Arc<OpenIDProviderConfiguration>,
    interaction_service: Arc<CoreInteractionService>,
    interaction_manager: Arc<InteractionManager>,
}

impl InteractionServiceImpl {
    pub fn new(provider: Arc<OpenIDProviderConfiguration>) -> Self {
        let keystore_service = Arc::new(KeystoreService::new(provider.clone()));
        let grant_manager = Arc::new(GrantManager::new(provider.clone()));
        let interaction_manager = Arc::new(InteractionManager::new(provider.clone()));
        let prompt_service = Arc::new(PromptService::new(
            provider.clone(),
            keystore_service.clone(),
        ));
        let interaction_service = Arc::new(CoreInteractionService::new(
            provider.clone(),
            prompt_service.clone(),
        ));
        let authorisation_service = AuthorisationService::new(
            DynamicResponseTypeResolver::from(provider.as_ref()),
            DynamicResponseModeEncoder,
            provider.clone(),
            interaction_service.clone(),
            grant_manager.clone(),
            keystore_service.clone(),
        );
        Self {
            authorisation_service,
            provider,
            interaction_service,
            interaction_manager,
        }
    }
}

#[tonic::async_trait]
impl InteractionService for InteractionServiceImpl {
    async fn get_interaction_info(
        &self,
        request: Request<InteractionInfoRequest>,
    ) -> Result<Response<InteractionInfoReply>, Status> {
        let request = request.into_inner();
        let interaction_id = Uuid::try_parse(request.interaction_id.as_str()).map_err(|err| {
            Status::invalid_argument(format!("Failed to parse interaction id. {err}"))
        })?;
        let interaction = self
            .interaction_manager
            .find(interaction_id)
            .await
            .map_err(convert_persistence_err)?
            .ok_or_else(|| {
                Status::not_found(format!("Interaction with id {interaction_id} not found"))
            })?;
        Ok(Response::new(interaction.into()))
    }

    async fn get_client_info(
        &self,
        request: Request<ClientInfoRequest>,
    ) -> Result<Response<ClientInfo>, Status> {
        let request = request.into_inner();
        let client_id = ClientID::from_str(request.client_id.as_str())
            .map_err(|err| Status::invalid_argument(format!("Failed to parse client id. {err}")))?;
        let client = retrieve_client_info(&self.provider, client_id)
            .await
            .map_err(convert_client_err)?
            .ok_or_else(|| Status::not_found(format!("Client with id {client_id} not found")))?;
        Ok(Response::new(client.into()))
    }

    async fn complete_login(
        &self,
        request: Request<CompleteLoginRequest>,
    ) -> Result<Response<CompleteLoginReply>, Status> {
        let c_request = request.into_inner();
        let interaction_id = Uuid::try_parse(c_request.interaction_id.as_str()).map_err(|err| {
            Status::invalid_argument(format!("Failed to parse interaction id. {err}"))
        })?;
        let redirect_uri = self
            .interaction_service
            .complete_login(
                interaction_id,
                Subject::new(c_request.sub),
                c_request.acr.map(Acr::from),
                c_request.amr.map(Amr::from),
            )
            .await
            .map_err(convert_err)?;
        Ok(Response::new(CompleteLoginReply {
            redirect_uri: redirect_uri.to_string(),
        }))
    }

    async fn confirm_consent(
        &self,
        request: Request<ConfirmConsentRequest>,
    ) -> Result<Response<ConfirmConsentReply>, Status> {
        let request = request.into_inner();
        let interaction_id = Uuid::try_parse(request.interaction_id.as_str()).map_err(|err| {
            Status::invalid_argument(format!("Failed to parse interaction id. {err}"))
        })?;
        let scopes = Scopes::from(request.scopes);
        let redirect_uri = self
            .interaction_service
            .confirm_consent(&self.authorisation_service, interaction_id, scopes)
            .await
            .map_err(convert_err)?;
        Ok(Response::new(ConfirmConsentReply {
            redirect_uri: redirect_uri.to_string(),
        }))
    }
}

impl From<Interaction> for InteractionInfoReply {
    fn from(interaction: Interaction) -> Self {
        match interaction {
            Interaction::Login {
                id,
                session,
                request,
                ..
            } => InteractionInfoReply {
                interaction_id: id.to_string(),
                session_id: session.to_string(),
                r#type: InteractionType::Login as i32,
                request: Some(request.into()),
                user: None,
            },
            Interaction::Consent {
                id,
                session,
                request,
                user,
                ..
            } => InteractionInfoReply {
                interaction_id: id.to_string(),
                session_id: session.to_string(),
                r#type: InteractionType::Login as i32,
                request: Some(request.into()),
                user: Some(user.into()),
            },
            Interaction::None {
                id,
                session,
                request,
                user,
                ..
            } => InteractionInfoReply {
                interaction_id: id.to_string(),
                session_id: session.to_string(),
                r#type: InteractionType::Login as i32,
                request: Some(request.into()),
                user: Some(user.into()),
            },
        }
    }
}

impl From<ValidatedAuthorisationRequest> for AuthorisationRequestInfo {
    fn from(req: ValidatedAuthorisationRequest) -> Self {
        AuthorisationRequestInfo {
            response_mode: req.response_mode.map(|rm| rm.to_string()),
            response_type: req.response_type.to_string(),
            client_id: req.client_id.to_string(),
            redirect_uri: req.redirect_uri.to_string(),
            scopes: req.scope.iter().map(|it| it.to_string()).collect(),
            state: req.state.map(|s| s.to_string()),
            nonce: req.nonce.map(|n| n.to_string()),
            code_challenge: req.code_challenge.map(|cc| cc.to_string()),
            code_challenge_method: req.code_challenge_method.map(|ccm| ccm.to_string()),
            resource: req.resource.map(|r| r.to_string()),
            include_granted_scopes: req.include_granted_scopes,
            prompt: req.prompt.map(|p| {
                p.iter()
                    .map(|it| it.to_string())
                    .collect::<Vec<String>>()
                    .join(" ")
            }),
            requested_acr: req
                .acr_values
                .map(|it| it.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default(),
            login_hint: req.login_hint,
        }
    }
}

impl From<AuthenticatedUser> for AuthenticatedUserInfo {
    fn from(user: AuthenticatedUser) -> Self {
        AuthenticatedUserInfo {
            sub: user.sub().into(),
            auth_time: user.auth_time().to_string(),
        }
    }
}

impl From<ClientInformation> for ClientInfo {
    fn from(client: ClientInformation) -> Self {
        let id = client.id();
        let metadata = client.consume_metadata();
        ClientInfo {
            id: id.to_string(),
            scope: metadata.scope.to_string(),
            redirect_uris: metadata
                .redirect_uris
                .into_iter()
                .map(|it| it.to_string())
                .collect(),
            grant_types: metadata
                .grant_types
                .into_iter()
                .map(|it| it.to_string())
                .collect(),
            response_types: metadata
                .response_types
                .into_iter()
                .map(|it| it.to_string())
                .collect(),
            contacts: metadata.contacts,
            token_endpoint_auth_method: metadata.token_endpoint_auth_method.to_string(),
            client_name: metadata.client_name,
            client_uri: metadata.client_uri.map(|it| it.to_string()),
            logo_uri: metadata.logo_uri.map(|it| it.to_string()),
            tos_uri: metadata.tos_uri.map(|it| it.to_string()),
            policy_uri: metadata.policy_uri.map(|it| it.to_string()),
            jwks_uri: metadata.jwks_uri.map(|it| it.to_string()),
            software_id: metadata.software_id.map(|it| it.to_string()),
            software_version: metadata.software_version,
        }
    }
}

fn convert_err(err: InteractionError) -> Status {
    match err {
        InteractionError::FailedPreCondition(_) => Status::failed_precondition(err.to_string()),
        InteractionError::NotFound(_) => Status::not_found(err.to_string()),
        InteractionError::ClientNotFound(_) => Status::invalid_argument(err.to_string()),
        InteractionError::Internal(_) => Status::internal(err.to_string()),
        InteractionError::Persistence(_) => Status::internal(err.to_string()),
        InteractionError::Authorization(_) => Status::internal(err.to_string()),
        InteractionError::PromptError(_) => Status::internal(err.to_string()),
    }
}

fn convert_client_err(err: ClientError) -> Status {
    Status::internal(err.to_string())
}

fn convert_persistence_err(err: PersistenceError) -> Status {
    Status::internal(err.to_string())
}
