use std::sync::Arc;

use thiserror::Error;

use oidc_types::client::ClientInformation;
use oidc_types::url_encodable::UrlEncodable;

use crate::adapter::PersistenceError;
use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::OpenIDProviderConfiguration;
use crate::context::OpenIDContext;
use crate::response_mode::encoder::{
    encode_response, AuthorisationResponse, EncodingContext, ResponseModeEncoder,
};
use crate::response_type::resolver::ResponseTypeResolver;
use crate::services::interaction::begin_interaction;
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

#[derive(Error, Debug)]
pub enum AuthorisationError {
    #[error("Invalid redirect_uri")]
    InvalidRedirectUri,
    #[error("Invalid client {}", .0)]
    InvalidClient(String),
    #[error("Missing client")]
    MissingClient,
    #[error(transparent)]
    InteractionErr(PersistenceError),
    #[error(transparent)]
    InternalError(#[from] anyhow::Error),
}

pub struct AuthorisationService<R, E> {
    resolver: R,
    encoder: E,
    configuration: Arc<OpenIDProviderConfiguration>,
}

impl<R, E> AuthorisationService<R, E>
where
    R: ResponseTypeResolver,
    E: ResponseModeEncoder,
{
    pub fn new(resolver: R, encoder: E, configuration: Arc<OpenIDProviderConfiguration>) -> Self {
        Self {
            resolver,
            encoder,
            configuration,
        }
    }

    pub async fn authorise(
        &self,
        session: SessionID,
        client: ClientInformation,
        request: ValidatedAuthorisationRequest,
    ) -> Result<AuthorisationResponse, AuthorisationError> {
        let interaction = begin_interaction(&self.configuration, session, request).await?;
        match interaction {
            Interaction::Login { .. } | Interaction::Consent { .. } => Ok(
                AuthorisationResponse::Redirect(interaction.uri(&self.configuration)),
            ),
            Interaction::None { request, user, .. } => {
                Ok(self.do_authorise(user, client, request).await?)
            }
        }
    }

    pub async fn do_authorise(
        &self,
        user: AuthenticatedUser,
        client: ClientInformation,
        request: ValidatedAuthorisationRequest,
    ) -> Result<AuthorisationResponse, AuthorisationError> {
        let client = Arc::new(client);
        let context = OpenIDContext::new(client.clone(), user, request, self.configuration.clone());
        let auth_result = self.resolver.resolve(&context).await;

        let encoding_context = EncodingContext {
            client: &client,
            configuration: &self.configuration,
            redirect_uri: &context.request.redirect_uri,
            response_mode: context
                .request
                .response_mode(self.configuration.jwt_secure_response_mode()),
        };
        let mut parameters = auth_result.map_or_else(UrlEncodable::params, UrlEncodable::params);
        if let Some(state) = context.request.state {
            parameters = (parameters, state).params();
        }
        encode_response(encoding_context, &self.encoder, parameters)
    }
}
