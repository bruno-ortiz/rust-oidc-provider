use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use thiserror::Error;

use oidc_types::client::{ClientID, ClientInformation};
use oidc_types::response_mode::ResponseMode;
use oidc_types::subject::Subject;
use oidc_types::url_encodable::UrlEncodable;

use crate::authorisation_request::AuthorisationRequest;
use crate::client::ClientService;
use crate::configuration::OpenIDProviderConfiguration;
use crate::context::OpenIDContext;
use crate::response_mode::encoder::fragment::FragmentEncoder;
use crate::response_mode::encoder::query::QueryEncoder;
use crate::response_mode::encoder::{AuthorisationResponse, EncodingContext, ResponseModeEncoder};
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::ResponseTypeResolver;

#[derive(Error, Debug)]
pub enum AuthorisationError {
    #[error("Invalid redirect_uri")]
    InvalidRedirectUri,
    #[error("Invalid client")]
    InvalidClient,
    #[error("Missing client")]
    MissingClient,
    #[error(transparent)]
    InternalError(#[from] anyhow::Error),
}

struct AuthorisationService<R: ResponseTypeResolver, E: ResponseModeEncoder> {
    resolver: R,
    encoder: E,
    client_service: Arc<ClientService>,
    configuration: Arc<OpenIDProviderConfiguration>,
}

impl<R, E> AuthorisationService<R, E>
where
    R: ResponseTypeResolver,
    E: ResponseModeEncoder,
{
    pub async fn authorise(
        self,
        subject: Subject,
        request: AuthorisationRequest,
    ) -> Result<AuthorisationResponse, AuthorisationError> {
        let client_id = request
            .client_id
            .as_ref()
            .ok_or(AuthorisationError::MissingClient)?;
        let client = self
            .client_service
            .retrieve_client_info(client_id, &self.configuration)
            .await
            .ok_or(AuthorisationError::InvalidClient)
            .map(Arc::new)?;

        Self::validate_redirect_uri(&request, &client)?;
        match request.validate(&client) {
            Ok(validated_req) => {
                let context = OpenIDContext::new(
                    client.clone(),
                    subject,
                    validated_req,
                    self.configuration.clone(),
                );
                let auth_result = self.exec_authorisation(&context).await;

                let encoding_context = EncodingContext {
                    client: &client,
                    configuration: &self.configuration,
                    redirect_uri: &context.request.redirect_uri,
                    response_mode: context
                        .request
                        .response_mode(self.configuration.is_jarm_enabled()),
                };
                match auth_result {
                    Ok(res) => Ok(self.encode_response(encoding_context, res.params())?),
                    Err(err) => Ok(self.encode_response(encoding_context, err)?),
                }
            }
            Err((err, request)) => {
                let redirect_uri = request
                    .redirect_uri
                    .as_ref()
                    .ok_or(AuthorisationError::InvalidRedirectUri)?;
                let response_mode = request
                    .response_type
                    .as_ref()
                    .map_or(ResponseMode::Query, |rt| rt.default_response_mode());

                let encoding_context = EncodingContext {
                    client: &client,
                    configuration: &self.configuration,
                    redirect_uri,
                    response_mode,
                };
                Ok(self.encode_response(encoding_context, err)?)
            }
        }
    }

    fn validate_redirect_uri(
        request: &AuthorisationRequest,
        client: &ClientInformation,
    ) -> Result<(), AuthorisationError> {
        let redirect_uri = request
            .redirect_uri
            .as_ref()
            .ok_or(AuthorisationError::InvalidRedirectUri)?;
        if client.metadata.redirect_uris.contains(redirect_uri) {
            Ok(())
        } else {
            Err(AuthorisationError::InvalidRedirectUri)
        }
    }

    async fn exec_authorisation(
        &self,
        context: &OpenIDContext,
    ) -> Result<HashMap<String, String>, OpenIdError> {
        let rt = &context.request.response_type;
        if !context.server_allows_response_type(rt) {
            return Err(OpenIdError::UnsupportedResponseType(rt.clone()));
        }
        if !context.client_allows_response_type(rt) {
            return Err(OpenIdError::UnauthorizedClient {
                source: anyhow!("Invalid response type for client"),
            });
        }
        let parameters = self.resolver.resolve(&context).await?;
        Ok(parameters.params())
    }

    fn encode_response<T: UrlEncodable>(
        &self,
        context: EncodingContext,
        parameters: T,
    ) -> Result<AuthorisationResponse, AuthorisationError> {
        let result = self
            .encoder
            .encode(&context, parameters.params())
            .map_err(|err| OpenIdError::ServerError { source: err.into() });
        match result {
            Ok(res) => Ok(res),
            Err(err) => Self::encode_err(&context, err),
        }
    }

    fn encode_err(
        context: &EncodingContext,
        err: OpenIdError,
    ) -> Result<AuthorisationResponse, AuthorisationError> {
        match context.response_mode {
            ResponseMode::Fragment => FragmentEncoder
                .encode(context, err.params())
                .map_err(|err| AuthorisationError::InternalError(err.into())),
            ResponseMode::Query => QueryEncoder
                .encode(context, err.params())
                .map_err(|err| AuthorisationError::InternalError(err.into())),
            _ => Err(AuthorisationError::InternalError(err.into())),
        }
    }
}
