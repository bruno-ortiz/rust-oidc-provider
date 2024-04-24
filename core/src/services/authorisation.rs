use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use anyhow::{anyhow, Context};
use derive_new::new;
use thiserror::Error;
use url::Url;

use oidc_types::response_mode::ResponseMode;
use oidc_types::state::State;
use oidc_types::url_encodable::UrlEncodable;

use crate::adapter::PersistenceError;
use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::client::ClientError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::manager::grant_manager::GrantManager;
use crate::models::client::ClientInformation;
use crate::models::grant::{Grant, GrantID};
use crate::persistence::TransactionId;
use crate::prompt::PromptError;
use crate::response_mode::encoder::EncodingContext;
use crate::response_mode::Authorisation;
use crate::response_type::resolver::ResponseTypeResolver;
use crate::services::interaction::{InteractionError, InteractionService};
use crate::services::keystore::KeystoreService;
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

#[derive(Error)]
pub enum AuthorisationError {
    #[error("Invalid redirect_uri")]
    InvalidRedirectUri,
    #[error("Missing redirect_uri")]
    MissingRedirectUri,
    #[error("Invalid client {}", .0)]
    InvalidClient(#[from] ClientError),
    #[error("Missing client")]
    MissingClient,
    #[error("Err: {}", .err)]
    RedirectableErr {
        #[source]
        err: OpenIdError,
        response_mode: ResponseMode,
        redirect_uri: Url,
        state: Option<State>,
        provider: Arc<OpenIDProviderConfiguration>,
        keystore_service: Arc<KeystoreService>,
        client: Arc<ClientInformation>,
    },
    #[error(transparent)]
    InternalError(#[from] anyhow::Error),
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

impl Debug for AuthorisationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(new)]
pub struct AuthorisationService<R> {
    resolver: R,
    provider: Arc<OpenIDProviderConfiguration>,
    interaction_service: Arc<InteractionService>,
    grant_manager: Arc<GrantManager>,
    keystore_service: Arc<KeystoreService>,
}

impl<R> AuthorisationService<R>
where
    R: ResponseTypeResolver,
{
    pub async fn authorise(
        &self,
        session: SessionID,
        client: Arc<ClientInformation>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<Authorisation, AuthorisationError> {
        let txn_manager = self.provider.adapter().transaction_manager();
        let txn_id = txn_manager.begin_txn().await?;

        let interaction = self
            .interaction_service
            .begin_interaction(session, request, client.clone(), txn_id.clone())
            .await
            .map_err(|err| {
                handle_prompt_err(
                    err,
                    self.provider.clone(),
                    client.clone(),
                    self.keystore_service.clone(),
                )
            })?;

        let response = match interaction {
            Interaction::Login { .. } | Interaction::Consent { .. } => {
                Authorisation::Redirect(interaction.uri(&self.provider))
            }
            Interaction::None { request, user, .. } => {
                let grant_id = user.grant_id().ok_or_else(|| {
                    AuthorisationError::InternalError(anyhow!(
                        "Trying to authorise user with no grant"
                    ))
                })?;
                let grant = self.find_grant(grant_id).await?;
                self.do_authorise(user, grant, client, request, txn_id.clone())
                    .await?
            }
        };
        txn_manager.commit(txn_id).await?;
        Ok(response)
    }

    pub async fn do_authorise(
        &self,
        user: AuthenticatedUser,
        grant: Grant,
        client: Arc<ClientInformation>,
        request: ValidatedAuthorisationRequest,
        txn_id: TransactionId,
    ) -> Result<Authorisation, AuthorisationError> {
        let context = OpenIDContext::new(
            client.clone(),
            user,
            request,
            grant,
            &self.provider,
            self.keystore_service.clone(),
            txn_id.clone(),
        );
        let auth_result = self.resolver.resolve(&context).await;

        let encoding_context = EncodingContext {
            client: &client,
            redirect_uri: &context.request.redirect_uri,
            response_mode: context
                .request
                .response_mode(self.provider.jwt_secure_response_mode()),
            provider: self.provider.as_ref(),
            keystore_service: &self.keystore_service,
        };
        let mut parameters = auth_result.map_or_else(UrlEncodable::params, UrlEncodable::params);
        if let Some(state) = context.request.state {
            parameters = (parameters, state).params();
        }
        Ok(Authorisation::new(encoding_context, parameters)
            .context("Error creating authorisation response")?)
    }

    async fn find_grant(&self, grant_id: GrantID) -> Result<Grant, AuthorisationError> {
        let grant = self
            .grant_manager
            .find_active(grant_id)
            .await
            .map_err(|err| AuthorisationError::InternalError(err.into()))?
            .ok_or_else(|| {
                AuthorisationError::InternalError(anyhow!("User has not granted access to data"))
            })?;
        Ok(grant)
    }
}

fn handle_prompt_err(
    err: InteractionError,
    provider: Arc<OpenIDProviderConfiguration>,
    client: Arc<ClientInformation>,
    keystore_service: Arc<KeystoreService>,
) -> AuthorisationError {
    let description = err.to_string();
    match err {
        InteractionError::PromptError(PromptError::LoginRequired {
            redirect_uri,
            response_mode,
            state,
        }) => AuthorisationError::RedirectableErr {
            err: OpenIdError::login_required(description),
            redirect_uri,
            response_mode,
            state,
            provider,
            keystore_service,
            client,
        },
        InteractionError::PromptError(PromptError::ConsentRequired {
            redirect_uri,
            response_mode,
            state,
        }) => AuthorisationError::RedirectableErr {
            err: OpenIdError::consent_required(description),
            redirect_uri,
            response_mode,
            state,
            provider,
            keystore_service,
            client,
        },
        _ => AuthorisationError::InternalError(err.into()),
    }
}
