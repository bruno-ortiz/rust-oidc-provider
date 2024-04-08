use std::sync::Arc;

use oidc_types::introspection::{
    IntrospectionRequestBody, IntrospectionResponse, IntrospectionResponseBuilder,
};
use tracing::debug;

use crate::{
    configuration::OpenIDProviderConfiguration,
    error::OpenIdError,
    models::{
        access_token::TokenError,
        client::{AuthenticatedClient, ClientInformation},
        token::{ActiveToken, Token, ACCESS_TOKEN, REFRESH_TOKEN},
    },
    utils::resolve_sub,
};

use super::token::TokenService;

const SUPPORTED_TOKEN_TYPES: [&str; 2] = [ACCESS_TOKEN, REFRESH_TOKEN];

pub struct IntrospectionService {
    provider: Arc<OpenIDProviderConfiguration>,
    token_service: Arc<TokenService>,
}

impl IntrospectionService {
    pub fn new(
        provider: Arc<OpenIDProviderConfiguration>,
        token_service: Arc<TokenService>,
    ) -> Self {
        Self {
            provider,
            token_service,
        }
    }
    pub async fn introspect(
        &self,
        request: IntrospectionRequestBody,
        client: AuthenticatedClient,
    ) -> Result<IntrospectionResponse, OpenIdError> {
        let token_types = match request.token_type_hint {
            Some(hint) => vec![hint],
            None => SUPPORTED_TOKEN_TYPES
                .iter()
                .map(ToString::to_string)
                .collect(),
        };
        for token_type in token_types {
            match self
                .token_service
                .find_active_token_by_type(&request.token, &token_type)
                .await
            {
                Ok(active_token) => {
                    return self
                        .create_response(active_token, &client)
                        .map_err(OpenIdError::from)
                }
                Err(TokenError::NotFound | TokenError::InvalidGrant) => {
                    debug!("Token not found for type {}", token_type);
                    continue;
                }
                Err(TokenError::Expired) => {
                    return Ok(IntrospectionResponse::inactive());
                }
                Err(err) => return Err(OpenIdError::from(err)),
            }
        }

        Ok(IntrospectionResponse::inactive())
    }

    fn create_response<T: Token>(
        &self,
        at: ActiveToken<T>,
        client: &ClientInformation,
    ) -> anyhow::Result<IntrospectionResponse> {
        let sub = resolve_sub(&self.provider, at.grant().subject(), client)?;
        let exp_date = at.created() + at.expires_in();
        let mut builder = IntrospectionResponseBuilder::default()
            .active(true)
            .client_id(at.grant().client_id())
            .exp(exp_date.unix_timestamp() as u64)
            .iat(at.created().unix_timestamp() as u64)
            .sub(sub.into_inner());

        if let Some(scopes) = at.scopes() {
            builder = builder.scope(scopes.to_string());
        }
        if let Some(token_type) = at.token_type() {
            builder = builder.token_type(token_type.to_string());
        }
        Ok(builder.build()?)
    }
}
