use std::sync::Arc;

use thiserror::Error;

use oidc_types::client::ClientInformation;
use oidc_types::response_mode::ResponseMode;
use oidc_types::url_encodable::UrlEncodable;

use crate::adapter::PersistenceError;
use crate::authorisation_request::{AuthorisationRequest, ValidatedAuthorisationRequest};
use crate::configuration::OpenIDProviderConfiguration;
use crate::context::OpenIDContext;
use crate::response_mode::encoder::fragment::FragmentEncoder;
use crate::response_mode::encoder::query::QueryEncoder;
use crate::response_mode::encoder::{
    encode_response, AuthorisationResponse, EncodingContext, ResponseModeEncoder,
};
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::ResponseTypeResolver;
use crate::session::AuthenticatedUser;

#[derive(Error, Debug)]
pub enum AuthorisationError {
    #[error("Invalid redirect_uri")]
    InvalidRedirectUri,
    #[error("Invalid client")]
    InvalidClient,
    #[error("Missing client")]
    MissingClient,
    #[error(transparent)]
    InteractionErr(PersistenceError),
    #[error(transparent)]
    InternalError(#[from] anyhow::Error),
}

pub struct AuthorisationService<R, E>
where
    R: ResponseTypeResolver,
    E: ResponseModeEncoder,
{
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
        user: AuthenticatedUser,
        client: Arc<ClientInformation>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<AuthorisationResponse, AuthorisationError> {
        let context = OpenIDContext::new(client.clone(), user, request, self.configuration.clone());
        let auth_result = self.resolver.resolve(&context).await;

        let encoding_context = EncodingContext {
            client: &client,
            configuration: &self.configuration,
            redirect_uri: &context.request.redirect_uri,
            response_mode: context
                .request
                .response_mode(self.configuration.is_jarm_enabled()),
        };
        match auth_result {
            Ok(res) => Ok(encode_response(
                encoding_context,
                &self.encoder,
                res.params(),
            )?),
            Err(err) => Ok(encode_response(encoding_context, &self.encoder, err)?),
        }
    }
}
