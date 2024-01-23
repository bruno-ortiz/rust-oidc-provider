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
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;

use crate::adapter::PersistenceError;
use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::client::retrieve_client_info;
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::models::client::ClientInformation;
use crate::models::grant::{Grant, GrantBuilder};
use crate::prompt::{PromptError, PromptResolver};
use crate::response_mode::encoder::{AuthorisationResponse, ResponseModeEncoder};
use crate::response_type::resolver::ResponseTypeResolver;
use crate::services::authorisation::AuthorisationService;
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
    #[error("Unexpected error saving interaction")]
    Persistence(#[from] PersistenceError),
    #[error("Unexpected prompt error {}", .0)]
    PromptError(#[from] PromptError),
    #[error("Unexpected error authorizing user")]
    Authorization(anyhow::Error),
    #[error("Unexpected error resolving user interaction")]
    Internal(#[from] anyhow::Error),
}

pub async fn begin_interaction(
    session: SessionID,
    request: ValidatedAuthorisationRequest,
    client: Arc<ClientInformation>,
) -> Result<Interaction, InteractionError> {
    let config = OpenIDProviderConfiguration::instance();
    let user = AuthenticatedUser::find_by_session(session).await;
    let (user, request, prompt_resolver) =
        select_prompt_resolver(config, user, request, &client).await?;

    if let Some(resolver) = prompt_resolver {
        let interaction = resolver.resolve(session, user, request)?.save().await?;
        Ok(interaction)
    } else {
        Err(InteractionError::Internal(anyhow!(
            "Unable to resolve prompt: {:?}",
            request.prompt
        )))
    }
}
type PromptReturn<'a> = (
    Option<AuthenticatedUser>,
    ValidatedAuthorisationRequest,
    Option<&'a PromptResolver>,
);
async fn select_prompt_resolver<'a>(
    config: &'a OpenIDProviderConfiguration,
    user: Option<AuthenticatedUser>,
    request: ValidatedAuthorisationRequest,
    client: &ClientInformation,
) -> Result<PromptReturn<'a>, InteractionError> {
    let mut prompt_resolver: Option<&PromptResolver> = None;
    if let Some(requested_prompt) = &request.prompt {
        prompt_resolver = config
            .prompts()
            .iter()
            .find(|&p| requested_prompt.contains(&p.prompt()));
    } else {
        let prompt_checks = config.prompts();
        for checker in prompt_checks {
            if checker
                .should_run(config, user.as_ref(), &request, client)
                .await?
            {
                prompt_resolver = Some(checker);
                break;
            }
        }
    }
    Ok((user, request, prompt_resolver))
}

pub async fn complete_login(
    interaction_id: Uuid,
    subject: Subject,
    acr: Option<Acr>,
    amr: Option<Amr>,
) -> Result<Url, InteractionError> {
    let configuration = OpenIDProviderConfiguration::instance();
    let clock = configuration.clock_provider();
    match Interaction::find(interaction_id).await {
        Some(Interaction::Login {
            session, request, ..
        }) => {
            let user =
                AuthenticatedUser::new(session, subject, clock.now(), interaction_id, acr, amr)
                    .save()
                    .await?;

            let interaction = Interaction::consent(request, user).save().await?;
            Ok(interaction.uri())
        }
        None => Err(InteractionError::NotFound(interaction_id)),
        _ => Err(InteractionError::FailedPreCondition(
            "Expected to find login interaction".to_owned(),
        )),
    }
}

pub async fn confirm_consent<R, E>(
    auth_service: &AuthorisationService<R, E>,
    interaction_id: Uuid,
    scopes: Scopes,
) -> Result<Url, InteractionError>
where
    R: ResponseTypeResolver,
    E: ResponseModeEncoder,
{
    match Interaction::find(interaction_id).await {
        Some(Interaction::Consent { request, user, .. }) => {
            if let Some(old_grant_id) = user.grant_id() {
                if let Some(old_grant) = Grant::find(old_grant_id).await {
                    old_grant
                        .consume()
                        .await
                        .context(format!(
                            "Failed to consume old grant with id {} from user {}",
                            old_grant_id,
                            user.sub()
                        ))
                        .map_err(InteractionError::Internal)?;
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
                .expect("Should always build successfully")
                .save()
                .await?;

            let user = user.with_grant(grant.id()).save().await?;
            let client = retrieve_client_info(request.client_id)
                .await
                .ok_or(InteractionError::ClientNotFound(request.client_id))?;

            let (user, request) = finalize_interaction(request, user).await?;
            let res = auth_service
                .do_authorise(user, Arc::new(client), request)
                .await
                .map_err(|err| InteractionError::Authorization(err.into()))?;
            if let AuthorisationResponse::Redirect(url) = res {
                Ok(url)
            } else {
                Err(InteractionError::Internal(anyhow!("Not supported")))
            }
        }
        None => Err(InteractionError::NotFound(interaction_id)),
        _ => Err(InteractionError::FailedPreCondition(
            "Expected to find consent interaction".to_owned(),
        )),
    }
}

async fn finalize_interaction(
    request: ValidatedAuthorisationRequest,
    user: AuthenticatedUser,
) -> Result<(AuthenticatedUser, ValidatedAuthorisationRequest), InteractionError> {
    Interaction::none(request, user)
        .save()
        .await?
        .consume_authenticated()
        .ok_or_else(|| InteractionError::Internal(anyhow!("Unable to consume this interaction")))
}

fn prepare_grant_claims(request: &ValidatedAuthorisationRequest) -> Claims {
    let mut claims = if let Some(claims) = &request.claims {
        claims.clone()
    } else {
        Claims::default()
    };

    claims.handle_acr_values_parameter(request.acr_values.as_ref());
    claims
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
    use crate::models::client::ClientInformation;
    use crate::services::interaction::begin_interaction;
    use crate::services::types::Interaction;
    use crate::session::SessionID;
    use crate::user::AuthenticatedUser;

    #[tokio::test]
    async fn test_begin_login_interaction_successful() {
        let session_id = SessionID::new();
        let auth_request = create_request(None, None, None);
        let result = begin_interaction(session_id, auth_request, create_client()).await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, .. }) = result else {
            panic!("Expected login interactions")
        };
        assert_eq!(session, session_id)
    }

    #[tokio::test]
    async fn test_begin_login_interaction_due_to_user_max_age_expired() {
        init_logging();
        let session_id = SessionID::new();
        let auth_request = create_request(None, None, Some(1));

        let result = begin_interaction(session_id, auth_request.clone(), create_client()).await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };

        let auth_time = OffsetDateTime::now_utc() - Duration::minutes(5);
        let user = AuthenticatedUser::new(session, Subject::new("sub"), auth_time, id, None, None)
            .save()
            .await
            .expect("User should be saved");

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let result = begin_interaction(session_id, auth_request, create_client()).await;
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

        let result =
            dbg!(begin_interaction(session_id, auth_request.clone(), create_client()).await);
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };

        let auth_time = OffsetDateTime::now_utc();
        let user = AuthenticatedUser::new(session, Subject::new("sub"), auth_time, id, None, None)
            .save()
            .await
            .expect("User should be saved");

        let request_with_prompt = create_request(Some(IndexSet::from([Prompt::Login])), None, None);
        let result = begin_interaction(session_id, request_with_prompt, create_client()).await;
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

        let result = begin_interaction(session_id, auth_request.clone(), create_client()).await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };

        let auth_time = OffsetDateTime::now_utc();
        let user = AuthenticatedUser::new(session, Subject::new("sub"), auth_time, id, None, None)
            .save()
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
        let result = begin_interaction(session_id, request_with_acr, create_client()).await;
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

        let result = begin_interaction(session_id, auth_request.clone(), create_client()).await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };

        let auth_time = OffsetDateTime::now_utc();
        let user = AuthenticatedUser::new(session, Subject::new("sub"), auth_time, id, None, None)
            .save()
            .await
            .expect("User should be saved");

        let request_with_acr =
            create_request(None, Some(Acr::new(vec!["acr:test:xpto".into()])), None);
        let result = begin_interaction(session_id, request_with_acr, create_client()).await;
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
}
