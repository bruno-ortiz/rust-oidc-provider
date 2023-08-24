use std::collections::HashSet;
use std::sync::Arc;

use anyhow::anyhow;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::client::ClientID;
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;

use crate::adapter::PersistenceError;
use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::client::retrieve_client_info;
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::models::grant::GrantBuilder;
use crate::prepare_claims;
use crate::prompt::none::NoneResolver;
use crate::prompt::{PromptChecker, PromptDispatcher, PromptError, PromptResolver};
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
    let user = AuthenticatedUser::find_by_session(session).await;
    let dispatchers = PromptDispatcher::default_dispatchers();

    let mut dispatcher = None;
    for checker in dispatchers {
        if checker.should_run(user.as_ref(), &request).await {
            dispatcher = Some(checker);
            break;
        }
    }
    let resolver = dispatcher.unwrap_or(PromptDispatcher::None(NoneResolver));
    let interaction = resolver
        .resolve(session, user, request)
        .await?
        .save()
        .await?;
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
                .claims(prepare_claims!(
                    request,
                    (acr_values, "acr"),
                    (max_age, "auth_time")
                ))
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

mod macros {
    #[macro_export]
    macro_rules! prepare_claims {
        ($req:ident, ($opt:ident, $claim:expr)$(,($opt2:ident, $claim2:expr))* ) => {
            {
                let request = &$req;
                if request.$opt.is_some() $(|| request.$opt2.is_some())*  {
                    let mut c = if let Some(claims) = &request.claims {
                        claims.clone()
                    } else {
                        oidc_types::claims::Claims::default()
                    };
                    if request.$opt.is_some() {
                        c.id_token.insert($claim.to_owned(), Some(oidc_types::claims::ClaimOptions::voluntary()));
                        c.userinfo.insert($claim.to_owned(), Some(oidc_types::claims::ClaimOptions::voluntary()));
                    }
                    $(
                      if request.$opt2.is_some() {
                        c.id_token.insert($claim2.to_owned(), Some(oidc_types::claims::ClaimOptions::voluntary()));
                        c.userinfo.insert($claim2.to_owned(), Some(oidc_types::claims::ClaimOptions::voluntary()));
                      }
                    )*
                    Some(c)
                } else {
                    request.claims.clone()
                }
            }
        };
    }
}
