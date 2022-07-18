use format as f;
use oidc_types::grant::Grant;
use oidc_types::prompt::Prompt;
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use oidc_types::subject::Subject;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::OpenIDProviderConfiguration;
use crate::services::authorisation::AuthorisationError;
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::{find_user_by_session, AuthenticatedUser};

#[derive(Debug, Error)]
pub enum InteractionError {
    #[error("{}", .0)]
    FailedPreCondition(String),
    #[error("Interaction not found for id {}", .0)]
    NotFound(Uuid),
    #[error("{}",.0)]
    Internal(String),
}

pub async fn begin_interaction(
    configuration: &OpenIDProviderConfiguration,
    session: SessionID,
    request: ValidatedAuthorisationRequest,
) -> Result<Interaction, AuthorisationError> {
    let interaction = resolve_interaction(configuration, session, request)
        .await
        .save(configuration)
        .await
        .map_err(AuthorisationError::InteractionErr)?;
    Ok(interaction)
}

pub async fn complete_login(
    configuration: &OpenIDProviderConfiguration,
    interaction_id: Uuid,
    subject: Subject,
) -> Result<Url, InteractionError> {
    match Interaction::find(configuration, interaction_id).await {
        Some(Interaction::Login {
            session, request, ..
        }) => {
            let user = AuthenticatedUser::new(
                session,
                subject,
                OffsetDateTime::now_utc(),
                *configuration.auth_max_age(),
            )
            .save(configuration)
            .await
            .map_err(|err| {
                InteractionError::Internal(f!("Unexpected error authenticating user. Err: {err}"))
            })?;

            let interaction = Interaction::consent(
                session,
                request,
                user,
                configuration.interaction_consent_url(),
            )
            .save(configuration)
            .await
            .map_err(|err| {
                InteractionError::Internal(f!("Unexpected error authenticating user. Err: {err}"))
            })?;
            Ok(interaction.uri())
        }
        None => Err(InteractionError::NotFound(interaction_id)),
        _ => Err(InteractionError::FailedPreCondition(
            "Expected to find login interaction".to_owned(),
        )),
    }
}

async fn resolve_interaction(
    config: &OpenIDProviderConfiguration,
    session: SessionID,
    request: ValidatedAuthorisationRequest,
) -> Interaction {
    let user = find_user_by_session(config, session).await;

    let prompt = request.prompt.as_ref();
    if user.is_none() || prompt.is_some() && prompt.unwrap().contains(&Prompt::Login) {
        Interaction::login(session, request, config.interaction_login_url())
    } else if let Some(user) = user {
        if !user.has_requested_grant(Grant::new(request.scope.clone()))
            || prompt.is_some() && prompt.unwrap().contains(&Prompt::Consent)
        {
            Interaction::consent(session, request, user, config.interaction_consent_url())
        } else {
            Interaction::none(session, request, user)
        }
    } else {
        Interaction::none(
            session,
            request,
            user.expect("User should be authenticated"),
        )
    }
}
