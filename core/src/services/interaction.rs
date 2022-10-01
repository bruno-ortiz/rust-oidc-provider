use anyhow::anyhow;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::client::ClientID;
use oidc_types::grant::Grant;
use oidc_types::prompt::Prompt;
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;

use crate::adapter::PersistenceError;
use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::client::retrieve_client_info;
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::response_mode::encoder::{AuthorisationResponse, ResponseModeEncoder};
use crate::response_type::resolver::ResponseTypeResolver;
use crate::services::authorisation::{AuthorisationError, AuthorisationService};
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::{find_user_by_session, AuthenticatedUser};

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
    #[error("Unexpected error authorizing user")]
    Authorization(#[from] AuthorisationError),
    #[error("Unexpected error resolving user interaction")]
    Internal(#[from] anyhow::Error),
}

pub async fn begin_interaction(
    session: SessionID,
    request: ValidatedAuthorisationRequest,
) -> Result<Interaction, AuthorisationError> {
    let interaction = resolve_interaction(session, request)
        .await
        .save()
        .await
        .map_err(AuthorisationError::InteractionErr)?;
    Ok(interaction)
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
                configuration.auth_max_age(),
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
            let user = user.with_grant(Grant::new(scopes)).save().await?;
            let client = retrieve_client_info(request.client_id)
                .await
                .ok_or(InteractionError::ClientNotFound(request.client_id))?;

            let (user, request) = finalize_interaction(request, user).await?;
            let res = auth_service.do_authorise(user, client, request).await?;
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

async fn resolve_interaction(
    session: SessionID,
    request: ValidatedAuthorisationRequest,
) -> Interaction {
    let user = find_user_by_session(session).await;

    let prompt = request.prompt.as_ref();
    if user.is_none() || prompt.is_some() && prompt.unwrap().contains(&Prompt::Login) {
        Interaction::login(session, request)
    } else if let Some(user) = user {
        if !user.has_requested_grant(&request.scope)
            || prompt.is_some() && prompt.unwrap().contains(&Prompt::Consent)
        {
            Interaction::consent(request, user)
        } else {
            Interaction::none(request, user)
        }
    } else {
        panic!("unreachable")
    }
}

async fn finalize_interaction(
    request: ValidatedAuthorisationRequest,
    user: AuthenticatedUser,
) -> Result<(AuthenticatedUser, ValidatedAuthorisationRequest), InteractionError> {
    Interaction::none(request, user)
        .save()
        .await?
        .consume()
        .ok_or_else(|| InteractionError::Internal(anyhow!("Unable to consume this interaction")))
}
