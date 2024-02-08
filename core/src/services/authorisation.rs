use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use anyhow::anyhow;
use derive_new::new;
use thiserror::Error;
use url::Url;

use oidc_types::response_mode::ResponseMode;
use oidc_types::state::State;
use oidc_types::url_encodable::UrlEncodable;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::client::ClientError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::manager::grant_manager::GrantManager;
use crate::models::client::ClientInformation;
use crate::models::grant::{Grant, GrantID};
use crate::prompt::PromptError;
use crate::response_mode::encoder::{
    encode_response, AuthorisationResponse, EncodingContext, ResponseModeEncoder,
};
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
}

impl Debug for AuthorisationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(new)]
pub struct AuthorisationService<R, E> {
    resolver: R,
    encoder: E,
    provider: Arc<OpenIDProviderConfiguration>,
    interaction_service: Arc<InteractionService>,
    grant_manager: Arc<GrantManager>,
    keystore_service: Arc<KeystoreService>,
}

impl<R, E> AuthorisationService<R, E>
where
    R: ResponseTypeResolver,
    E: ResponseModeEncoder,
{
    pub async fn authorise(
        &self,
        session: SessionID,
        client: Arc<ClientInformation>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<AuthorisationResponse, AuthorisationError> {
        let interaction = self
            .interaction_service
            .begin_interaction(session, request, client.clone())
            .await
            .map_err(|err| {
                handle_prompt_err(
                    err,
                    self.provider.clone(),
                    client.clone(),
                    self.keystore_service.clone(),
                )
            })?;
        match interaction {
            Interaction::Login { .. } | Interaction::Consent { .. } => Ok(
                AuthorisationResponse::Redirect(interaction.uri(&self.provider)),
            ),
            Interaction::None { request, user, .. } => {
                Ok(self.do_authorise(user, client, request).await?)
            }
        }
    }

    pub async fn do_authorise(
        &self,
        user: AuthenticatedUser,
        client: Arc<ClientInformation>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<AuthorisationResponse, AuthorisationError> {
        let grant_id = user.grant_id().ok_or_else(|| {
            AuthorisationError::InternalError(anyhow!("Trying to authorise user with no grant"))
        })?;
        let grant = self.find_grant(grant_id).await?;
        let context = OpenIDContext::new(
            client.clone(),
            user,
            request,
            grant,
            &self.provider,
            self.keystore_service.clone(),
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
        let parameters = auth_result.map_or_else(UrlEncodable::params, UrlEncodable::params);
        encode_response(
            encoding_context,
            &self.encoder,
            parameters,
            context.request.state,
        )
    }

    async fn find_grant(&self, grant_id: GrantID) -> Result<Grant, AuthorisationError> {
        let grant = self
            .grant_manager
            .find(grant_id)
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
