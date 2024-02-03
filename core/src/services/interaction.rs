use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::claims::Claims;
use oidc_types::client::ClientID;
use oidc_types::prompt::Prompt;
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;
use InteractionError::Internal;

use crate::adapter::PersistenceError;
use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::client::retrieve_client_info;
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::manager::grant_manager::GrantManager;
use crate::manager::interaction_manager::InteractionManager;
use crate::manager::user_manager::UserManager;
use crate::models::client::ClientInformation;
use crate::models::grant::GrantBuilder;
use crate::prompt::PromptError;
use crate::response_mode::encoder::{AuthorisationResponse, ResponseModeEncoder};
use crate::response_type::resolver::ResponseTypeResolver;
use crate::services::authorisation::AuthorisationService;
use crate::services::prompt::PromptService;
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

#[derive(Debug, Error)]
pub enum InteractionError {
    #[error("{}", .0)]
    FailedPreCondition(String),
    #[error("Interaction not found for id {}", .0)]
    NotFound(Uuid),
    #[error("Client not found for id {}", .0)]
    ClientNotFound(ClientID),
    #[error("Unexpected error saving interaction: {}", .0)]
    Persistence(#[from] PersistenceError),
    #[error("Unexpected prompt error {}", .0)]
    PromptError(#[from] PromptError),
    #[error("Unexpected error authorizing user: {}",.0)]
    Authorization(anyhow::Error),
    #[error("Unexpected error resolving user interaction")]
    Internal(#[from] anyhow::Error),
}

pub struct InteractionService {
    provider: Arc<OpenIDProviderConfiguration>,
    prompt_service: Arc<PromptService>,
    interaction_manager: InteractionManager,
    grant_manager: GrantManager,
    user_manager: UserManager,
}

impl InteractionService {
    pub fn new(
        provider: Arc<OpenIDProviderConfiguration>,
        prompt_service: Arc<PromptService>,
    ) -> Self {
        let user_manager = UserManager::new(provider.clone());
        let grant_manager = GrantManager::new(provider.clone());
        let interaction_manager = InteractionManager::new(provider.clone());

        Self {
            provider,
            interaction_manager,
            grant_manager,
            user_manager,
            prompt_service,
        }
    }

    pub async fn begin_interaction(
        &self,
        session: SessionID,
        request: ValidatedAuthorisationRequest,
        client: Arc<ClientInformation>,
    ) -> Result<Interaction, InteractionError> {
        let user = self.user_manager.find_by_session(session).await?;
        let prompt = self
            .prompt_service
            .resolve_prompt(&request, user.as_ref(), &client)
            .await?;
        if let Some(prompt) = prompt {
            let interaction = self
                .select_interaction_for_prompt(prompt, session, user, request)
                .await?;
            Ok(interaction)
        } else {
            Err(Internal(anyhow!(
                "Unable to resolve prompt: {:?}",
                request.prompt
            )))
        }
    }

    pub async fn complete_login(
        &self,
        interaction_id: Uuid,
        subject: Subject,
        acr: Option<Acr>,
        amr: Option<Amr>,
    ) -> Result<Url, InteractionError> {
        let clock = self.provider.clock_provider();
        match self.interaction_manager.find(interaction_id).await {
            Ok(Some(Interaction::Login {
                session, request, ..
            })) => {
                let user =
                    AuthenticatedUser::new(session, subject, clock.now(), interaction_id, acr, amr);
                let user = self.user_manager.save(user, None).await?;

                let interaction =
                    Interaction::consent_with_id(user.interaction_id(), request, user);
                let interaction = self.interaction_manager.update(interaction).await?;
                Ok(interaction.uri(&self.provider))
            }
            Ok(None) => Err(InteractionError::NotFound(interaction_id)),
            _ => Err(InteractionError::FailedPreCondition(
                "Expected to find login interaction".to_owned(),
            )),
        }
    }

    pub async fn confirm_consent<R, E>(
        &self,
        auth_service: &AuthorisationService<R, E>,
        interaction_id: Uuid,
        scopes: Scopes,
    ) -> Result<Url, InteractionError>
    where
        R: ResponseTypeResolver,
        E: ResponseModeEncoder,
    {
        match self.interaction_manager.find(interaction_id).await {
            Ok(Some(Interaction::Consent { request, user, .. })) => {
                if let Some(old_grant_id) = user.grant_id() {
                    if let Some(old_grant) = self.grant_manager.find(old_grant_id).await? {
                        self.grant_manager
                            .consume(old_grant)
                            .await
                            .context(format!(
                                "Failed to consume old grant with id {} from user {}",
                                old_grant_id,
                                user.sub()
                            ))
                            .map_err(Internal)?;
                    }
                }

                let claims = prepare_grant_claims(&request);
                let grant = GrantBuilder::new()
                    .subject(user.sub().clone())
                    .scopes(scopes)
                    .acr(user.acr().clone())
                    .amr(user.amr().cloned())
                    .client_id(request.client_id)
                    .auth_time(user.auth_time())
                    .max_age(request.max_age)
                    .redirect_uri(request.redirect_uri.clone())
                    .rejected_claims(HashSet::new()) //todo: implement rejected claims
                    .claims(claims)
                    .build()
                    .map_err(|err| Internal(err.into()))?;
                let grant = self.grant_manager.save(grant).await?;

                let user = user.with_grant(grant.id());
                let user = self.user_manager.update(user, None).await?;
                let client = retrieve_client_info(&self.provider, request.client_id)
                    .await
                    .map_err(|err| Internal(err.into()))?
                    .ok_or(InteractionError::ClientNotFound(request.client_id))?;

                let (user, request) = self.finalize_interaction(request, user).await?;
                let res = auth_service
                    .do_authorise(user, Arc::new(client), request)
                    .await
                    .map_err(|err| InteractionError::Authorization(err.into()))?;
                if let AuthorisationResponse::Redirect(url) = res {
                    Ok(url)
                } else {
                    Err(Internal(anyhow!("Not supported")))
                }
            }
            Ok(None) => Err(InteractionError::NotFound(interaction_id)),
            _ => Err(InteractionError::FailedPreCondition(
                "Expected to find consent interaction".to_owned(),
            )),
        }
    }

    async fn finalize_interaction(
        &self,
        request: ValidatedAuthorisationRequest,
        user: AuthenticatedUser,
    ) -> Result<(AuthenticatedUser, ValidatedAuthorisationRequest), InteractionError> {
        let interaction = Interaction::none_with_id(user.interaction_id(), request, user);
        self.interaction_manager
            .update(interaction)
            .await?
            .consume_authenticated()
            .ok_or_else(|| Internal(anyhow!("Unable to consume this interaction")))
    }

    pub async fn select_interaction_for_prompt(
        &self,
        prompt: Prompt,
        session: SessionID,
        user: Option<AuthenticatedUser>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<Interaction, PromptError> {
        match prompt {
            Prompt::Login => {
                let interaction = Interaction::login(session, request);
                let saved_interaction = self.interaction_manager.save(interaction).await?;
                Ok(saved_interaction)
            }
            Prompt::Consent => {
                let user = user.ok_or_else(|| PromptError::login_required(&request))?;
                let new_id = Uuid::new_v4();
                let user = user.with_interaction(new_id);
                let user = self.user_manager.update(user, None).await?;
                let interaction = Interaction::consent_with_id(new_id, request, user);
                let saved_interaction = self.interaction_manager.save(interaction).await?;
                Ok(saved_interaction)
            }
            Prompt::None => {
                let user = user.ok_or_else(|| PromptError::login_required(&request))?;
                let new_id = Uuid::new_v4();
                let user = user.with_interaction(new_id);
                let user = self.user_manager.update(user, None).await?;
                let interaction = Interaction::none_with_id(new_id, request, user);
                let saved_interaction = self.interaction_manager.save(interaction).await?;
                Ok(saved_interaction)
            }
            Prompt::SelectAccount => todo!("Not implemented"),
        }
    }
}

fn prepare_grant_claims(request: &ValidatedAuthorisationRequest) -> Option<Claims> {
    if let Some(claims) = &request.claims {
        let mut claims = claims.clone();
        claims.handle_acr_values_parameter(request.acr_values.as_ref());
        Some(claims)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use indexmap::IndexSet;
    use josekit::jws::ES256;
    use time::{Duration, OffsetDateTime};
    use tracing::info;
    use url::Url;
    use uuid::Uuid;

    use oidc_types::acr::Acr;
    use oidc_types::application_type::ApplicationType;
    use oidc_types::auth_method::AuthMethod;
    use oidc_types::claims::{ClaimOptions, Claims};
    use oidc_types::client::{ClientID, ClientMetadata};
    use oidc_types::password_hasher::HasherConfig;
    use oidc_types::pkce::{CodeChallenge, CodeChallengeMethod};
    use oidc_types::prompt::Prompt;
    use oidc_types::response_type::ResponseTypeValue;
    use oidc_types::secret::HashedSecret;
    use oidc_types::subject::Subject;
    use oidc_types::subject_type::SubjectType;
    use oidc_types::{acr, response_type, scopes};

    use crate::authorisation_request::ValidatedAuthorisationRequest;
    use crate::configuration::OpenIDProviderConfiguration;
    use crate::context::test_utils::setup_provider;
    use crate::manager::interaction_manager::InteractionManager;
    use crate::manager::user_manager::UserManager;
    use crate::models::client::ClientInformation;
    use crate::services::interaction::InteractionService;
    use crate::services::prompt::PromptService;
    use crate::services::types::Interaction;
    use crate::session::SessionID;
    use crate::user::AuthenticatedUser;

    #[tokio::test]
    async fn test_begin_login_interaction_successful() {
        let session_id = SessionID::new();
        let provider = setup_provider();
        let service = prepare_service(Arc::new(provider));
        let auth_request = create_request(None, None, None);
        let result = service
            .begin_interaction(session_id, auth_request, create_client())
            .await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, .. }) = result else {
            panic!("Expected login interactions")
        };
        assert_eq!(session, session_id)
    }

    #[tokio::test]
    async fn test_begin_login_interaction_due_to_user_max_age_expired() {
        init_logging();
        let provider = Arc::new(setup_provider());
        let user_manager = UserManager::new(provider.clone());
        let service = prepare_service(provider.clone());
        let session_id = SessionID::new();
        let auth_request = create_request(None, None, Some(1));

        let result = service
            .begin_interaction(session_id, auth_request.clone(), create_client())
            .await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };

        let auth_time = OffsetDateTime::now_utc() - Duration::minutes(5);
        let user = AuthenticatedUser::new(session, Subject::new("sub"), auth_time, id, None, None);
        let user = user_manager
            .save(user, None)
            .await
            .expect("User should be saved");

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let result = service
            .begin_interaction(session_id, auth_request, create_client())
            .await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };
        assert_eq!(session_id, session);
        assert_ne!(user.interaction_id(), id);
    }

    #[tokio::test]
    async fn test_begin_login_interaction_due_to_prompt_request() {
        init_logging();
        let session_id = SessionID::new();
        let auth_request = create_request(None, None, None);
        let provider = Arc::new(setup_provider());
        let user_manager = UserManager::new(provider.clone());
        let service = prepare_service(provider.clone());

        let result = service
            .begin_interaction(session_id, auth_request.clone(), create_client())
            .await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };

        let auth_time = OffsetDateTime::now_utc();
        let user = AuthenticatedUser::new(session, Subject::new("sub"), auth_time, id, None, None);
        let user = user_manager
            .save(user, None)
            .await
            .expect("User should be saved");

        let request_with_prompt = create_request(Some(IndexSet::from([Prompt::Login])), None, None);
        let result = service
            .begin_interaction(session_id, request_with_prompt, create_client())
            .await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };
        assert_eq!(session_id, session);
        assert_ne!(user.interaction_id(), id);
    }

    #[tokio::test]
    async fn test_begin_login_interaction_due_to_wrong_acr_values() {
        init_logging();
        let session_id = SessionID::new();
        let auth_request = create_request(None, None, None);
        let provider = Arc::new(setup_provider());
        let user_manager = UserManager::new(provider.clone());
        let service = prepare_service(provider.clone());
        let result = service
            .begin_interaction(session_id, auth_request.clone(), create_client())
            .await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };

        let auth_time = OffsetDateTime::now_utc();
        let user = AuthenticatedUser::new(session, Subject::new("sub"), auth_time, id, None, None);
        let user = user_manager
            .save(user, None)
            .await
            .expect("User should be saved");

        let request_with_acr = create_request(
            None,
            Some(Acr::new(vec![
                "acr:test:xpto".into(),
                "acr:test:xpto2".into(),
            ])),
            None,
        );
        let result = service
            .begin_interaction(session_id, request_with_acr, create_client())
            .await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };
        assert_eq!(session_id, session);
        assert_ne!(user.interaction_id(), id);
    }

    #[tokio::test]
    async fn test_begin_login_interaction_due_to_wrong_acr_value() {
        init_logging();
        let session_id = SessionID::new();
        let auth_request = create_request(None, None, None);
        let provider = Arc::new(setup_provider());
        let user_manager = UserManager::new(provider.clone());
        let service = prepare_service(provider.clone());
        let result = service
            .begin_interaction(session_id, auth_request.clone(), create_client())
            .await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };

        let auth_time = OffsetDateTime::now_utc();
        let user = AuthenticatedUser::new(session, Subject::new("sub"), auth_time, id, None, None);
        let user = user_manager
            .save(user, None)
            .await
            .expect("User should be saved");

        let request_with_acr =
            create_request(None, Some(Acr::new(vec!["acr:test:xpto".into()])), None);
        let result = service
            .begin_interaction(session_id, request_with_acr, create_client())
            .await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };
        assert_eq!(session_id, session);
        assert_ne!(user.interaction_id(), id);
    }

    fn create_request(
        prompt: Option<IndexSet<Prompt>>,
        acr: Option<Acr>,
        max_age: Option<u64>,
    ) -> ValidatedAuthorisationRequest {
        let mut claims = Claims::default();
        if let Some(acr) = &acr {
            let (v, vs) = acr.to_values();
            let c = ClaimOptions::essential(v, vs);
            claims.id_token.insert(acr::CLAIM_KEY.into(), Some(c));
        }
        ValidatedAuthorisationRequest {
            client_id: ClientID::new(Uuid::new_v4()),
            response_type: response_type!(ResponseTypeValue::Code),
            redirect_uri: Url::parse("https://test.com/callback").unwrap(),
            scope: scopes!("openid", "test"),
            state: None,
            nonce: None,
            response_mode: None,
            code_challenge: Some(CodeChallenge::new("some code here")),
            code_challenge_method: Some(CodeChallengeMethod::Plain),
            resource: None,
            include_granted_scopes: None,
            prompt,
            acr_values: acr,
            claims: Some(claims),
            max_age,
            id_token_hint: None,
            login_hint: None,
        }
    }

    //noinspection DuplicatedCode
    fn create_client() -> Arc<ClientInformation> {
        let client_id = ClientID::new(Uuid::new_v4());
        let (hashed, _) = HashedSecret::random(HasherConfig::Sha256).unwrap();
        let metadata = ClientMetadata {
            redirect_uris: vec![],
            token_endpoint_auth_method: AuthMethod::None,
            token_endpoint_auth_signing_alg: None,
            default_max_age: None,
            require_auth_time: false,
            default_acr_values: None,
            initiate_login_uri: None,
            grant_types: vec![],
            response_types: vec![],
            scope: scopes!("openid", "test"),
            client_name: None,
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            contacts: vec![],
            jwks_uri: None,
            jwks: None,
            sector_identifier_uri: None,
            subject_type: SubjectType::Public,
            id_token_signed_response_alg: ES256.into(),
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            software_id: None,
            software_version: None,
            software_statement: None,
            application_type: ApplicationType::Native,
            authorization_signed_response_alg: ES256.into(),
            request_uris: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
        };

        Arc::new(ClientInformation::new(
            client_id,
            OffsetDateTime::now_utc(),
            hashed,
            None,
            metadata,
        ))
    }

    fn init_logging() {
        if tracing_subscriber::fmt::try_init().is_ok() {
            info!("Log initialized")
        }
    }

    fn prepare_service(provider: Arc<OpenIDProviderConfiguration>) -> InteractionService {
        let interaction_manager = Arc::new(InteractionManager::new(provider.clone()));
        let prompt_service = Arc::new(PromptService::new(provider.clone()));
        InteractionService::new(provider.clone(), prompt_service)
    }
}
