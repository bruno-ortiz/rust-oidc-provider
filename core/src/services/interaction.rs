use std::collections::HashSet;
use std::sync::Arc;

use anyhow::anyhow;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use oidc_types::acr;
use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::claims::{ClaimOptions, Claims};
use oidc_types::client::ClientID;
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;

use crate::adapter::PersistenceError;
use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::client::retrieve_client_info;
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::models::grant::GrantBuilder;
use crate::prompt::PromptError;
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
) -> Result<Interaction, InteractionError> {
    let config = OpenIDProviderConfiguration::instance();
    let user = AuthenticatedUser::find_by_session(session)
        .await
        .map(Arc::new);
    let request = Arc::new(request);
    let mut dispatcher = None;

    let (user, request) = {
        let prompt_checks = config.prompts();
        for checker in prompt_checks {
            if checker.should_run(user.clone(), request.clone()).await {
                dispatcher = Some(checker);
                break;
            }
        }
        (user.and_then(Arc::into_inner), Arc::into_inner(request))
    };

    let request = request.ok_or(InteractionError::Internal(anyhow!("Err")))?;
    if let Some(resolver) = dispatcher {
        let interaction = resolver
            .resolve(session, user, request)
            .await?
            .save()
            .await?;
        Ok(interaction)
    } else {
        Err(InteractionError::Internal(anyhow!(
            "Unable to resolve prompt: {:?}",
            request.prompt
        )))
    }
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
            let user = AuthenticatedUser::new(
                session,
                subject,
                clock.now(),
                request.max_age.unwrap_or(configuration.auth_max_age()),
                interaction_id,
                acr,
                amr,
            )
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
    use indexmap::IndexSet;
    use time::{Duration, OffsetDateTime};
    use tracing::info;
    use url::Url;
    use uuid::Uuid;

    use oidc_types::acr::Acr;
    use oidc_types::claims::{ClaimOptions, Claims};
    use oidc_types::client::ClientID;
    use oidc_types::pkce::{CodeChallenge, CodeChallengeMethod};
    use oidc_types::prompt::Prompt;
    use oidc_types::response_type::ResponseTypeValue;
    use oidc_types::subject::Subject;
    use oidc_types::{acr, response_type, scopes};

    use crate::authorisation_request::ValidatedAuthorisationRequest;
    use crate::services::interaction::begin_interaction;
    use crate::services::types::Interaction;
    use crate::session::SessionID;
    use crate::user::AuthenticatedUser;

    #[tokio::test]
    async fn test_begin_login_interaction_successful() {
        let session_id = SessionID::new();
        let auth_request = create_request(None, None);
        let result = begin_interaction(session_id, auth_request).await;
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
        let auth_request = create_request(None, None);

        let result = begin_interaction(session_id, auth_request.clone()).await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };

        let auth_time = OffsetDateTime::now_utc() - Duration::minutes(5);
        let max_age = Duration::minutes(2);
        let user = AuthenticatedUser::new(
            session,
            Subject::new("sub"),
            auth_time,
            max_age.whole_seconds() as u64,
            id,
            None,
            None,
        )
        .save()
        .await
        .expect("User should be saved");

        let result = begin_interaction(session_id, auth_request).await;
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
        let auth_request = create_request(None, None);

        let result = begin_interaction(session_id, auth_request.clone()).await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };

        let auth_time = OffsetDateTime::now_utc();
        let max_age = Duration::minutes(2);
        let user = AuthenticatedUser::new(
            session,
            Subject::new("sub"),
            auth_time,
            max_age.whole_seconds() as u64,
            id,
            None,
            None,
        )
        .save()
        .await
        .expect("User should be saved");

        let request_with_prompt = create_request(Some(IndexSet::from([Prompt::Login])), None);
        let result = begin_interaction(session_id, request_with_prompt).await;
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
        let auth_request = create_request(None, None);

        let result = begin_interaction(session_id, auth_request.clone()).await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };

        let auth_time = OffsetDateTime::now_utc();
        let max_age = Duration::minutes(2);
        let user = AuthenticatedUser::new(
            session,
            Subject::new("sub"),
            auth_time,
            max_age.whole_seconds() as u64,
            id,
            None,
            None,
        )
        .save()
        .await
        .expect("User should be saved");

        let request_with_acr = create_request(
            None,
            Some(Acr::new(vec![
                "acr:test:xpto".into(),
                "acr:test:xpto2".into(),
            ])),
        );
        let result = begin_interaction(session_id, request_with_acr).await;
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
        let auth_request = create_request(None, None);

        let result = begin_interaction(session_id, auth_request.clone()).await;
        assert!(result.is_ok());
        let Ok(Interaction::Login { session, id, .. }) = result else {
            panic!("Expected login interactions")
        };

        let auth_time = OffsetDateTime::now_utc();
        let max_age = Duration::minutes(2);
        let user = AuthenticatedUser::new(
            session,
            Subject::new("sub"),
            auth_time,
            max_age.whole_seconds() as u64,
            id,
            None,
            None,
        )
        .save()
        .await
        .expect("User should be saved");

        let request_with_acr = create_request(None, Some(Acr::new(vec!["acr:test:xpto".into()])));
        let result = begin_interaction(session_id, request_with_acr).await;
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
            request_uri: None,
            request: None,
            prompt,
            acr_values: acr,
            claims: Some(claims),
            max_age: None,
        }
    }

    fn init_logging() {
        if tracing_subscriber::fmt::try_init().is_ok() {
            info!("Log initialized")
        }
    }
}
