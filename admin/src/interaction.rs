use crate::oidc_admin::interaction_info_reply::InteractionType;
use crate::oidc_admin::interaction_service_server::InteractionService;
use crate::oidc_admin::{
    AuthenticatedUserInfo, AuthorisationRequestInfo, ClientInfo, ClientInfoRequest,
    CompleteLoginReply, CompleteLoginRequest, ConfirmConsentReply, ConfirmConsentRequest,
    InteractionInfoReply, InteractionInfoRequest,
};
use oidc_core::authorisation_request::ValidatedAuthorisationRequest;
use oidc_core::client::retrieve_client_info;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::response_mode::encoder::DynamicResponseModeEncoder;
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;
use oidc_core::services::authorisation::AuthorisationService;
use oidc_core::services::interaction::{complete_login, confirm_consent, InteractionError};
use oidc_core::services::types::Interaction;
use oidc_core::user::AuthenticatedUser;
use oidc_types::client::{ClientID, ClientInformation};
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;
use std::borrow::Borrow;
use std::str::FromStr;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct InteractionServiceImpl {
    configuration: Arc<OpenIDProviderConfiguration>,
    authorisation_service:
        AuthorisationService<DynamicResponseTypeResolver, DynamicResponseModeEncoder>,
}

impl InteractionServiceImpl {
    pub fn new(configuration: Arc<OpenIDProviderConfiguration>) -> Self {
        let authorisation_service = AuthorisationService::new(
            DynamicResponseTypeResolver::from(configuration.borrow()),
            DynamicResponseModeEncoder::from(configuration.borrow()),
            configuration.clone(),
        );
        Self {
            configuration,
            authorisation_service,
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
        let interaction = Interaction::find(&self.configuration, interaction_id)
            .await
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
        let client = retrieve_client_info(&self.configuration, client_id)
            .await
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
        let redirect_uri = complete_login(
            &self.configuration,
            interaction_id,
            Subject::new(c_request.sub),
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
        let redirect_uri = confirm_consent(
            &self.configuration,
            &self.authorisation_service,
            interaction_id,
            scopes,
        )
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
            request_uri: req.request_uri.map(|ru| ru.to_string()),
            prompt: req.prompt.map(|p| {
                p.iter()
                    .map(|it| it.to_string())
                    .collect::<Vec<String>>()
                    .join(" ")
            }),
        }
    }
}

impl From<AuthenticatedUser> for AuthenticatedUserInfo {
    fn from(user: AuthenticatedUser) -> Self {
        AuthenticatedUserInfo {
            sub: user.sub().into(),
            max_age: user.max_age() as i64,
            auth_time: user.auth_time().to_string(),
        }
    }
}

impl From<ClientInformation> for ClientInfo {
    fn from(client: ClientInformation) -> Self {
        ClientInfo {
            id: client.id.to_string(),
            scope: client.metadata.scope.to_string(),
            redirect_uris: client
                .metadata
                .redirect_uris
                .into_iter()
                .map(|it| it.to_string())
                .collect(),
            grant_types: client
                .metadata
                .grant_types
                .into_iter()
                .map(|it| it.to_string())
                .collect(),
            response_types: client
                .metadata
                .response_types
                .into_iter()
                .map(|it| it.to_string())
                .collect(),
            contacts: client.metadata.contacts,
            token_endpoint_auth_method: client
                .metadata
                .token_endpoint_auth_method
                .map(|it| it.to_string()),
            client_name: client.metadata.client_name,
            client_uri: client.metadata.client_uri.map(|it| it.to_string()),
            logo_uri: client.metadata.logo_uri.map(|it| it.to_string()),
            tos_uri: client.metadata.tos_uri.map(|it| it.to_string()),
            policy_uri: client.metadata.policy_uri.map(|it| it.to_string()),
            jwks_uri: client.metadata.jwks_uri.map(|it| it.to_string()),
            software_id: client.metadata.software_id.map(|it| it.to_string()),
            software_version: client.metadata.software_version,
        }
    }
}

fn convert_err(err: InteractionError) -> Status {
    match err {
        InteractionError::FailedPreCondition(_) => Status::failed_precondition(err.to_string()),
        InteractionError::NotFound(_) => Status::not_found(err.to_string()),
        InteractionError::Internal(_) => Status::internal(err.to_string()),
        InteractionError::ClientNotFound(_) => Status::invalid_argument(err.to_string()),
    }
}
