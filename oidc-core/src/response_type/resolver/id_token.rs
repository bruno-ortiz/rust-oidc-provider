use anyhow::anyhow;
use async_trait::async_trait;
use chrono::Utc;

use crate::access_token::AccessToken;
use crate::authorisation_code::AuthorisationCode;
use crate::context::OpenIDContext;
use crate::hash::TokenHasher;
use crate::id_token::IdToken;
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::ResponseTypeResolver;

pub struct IDTokenResolver<'a> {
    code: Option<&'a AuthorisationCode>,
    token: Option<&'a AccessToken>,
}

impl<'a> IDTokenResolver<'a> {
    pub fn new(code: Option<&'a AuthorisationCode>, token: Option<&'a AccessToken>) -> Self {
        IDTokenResolver { code, token }
    }
}
#[async_trait]
impl ResponseTypeResolver for IDTokenResolver<'_> {
    type Output = IdToken;

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let signing_key = context
            .configuration
            .signing_key()
            .ok_or(OpenIdError::ServerError {
                source: anyhow!("Missing signing key"),
            })?;
        let mut builder = IdToken::builder::<Utc>();
        if let Some(state) = context.request.state.as_ref() {
            let s_hash = state
                .hash(signing_key)
                .map_err(|source| OpenIdError::ServerError {
                    source: source.into(),
                })?;
            builder = builder.with_s_hash(s_hash);
        }
        let id_token = builder
            .build(signing_key)
            .map_err(|err| OpenIdError::ServerError { source: err.into() })?;
        Ok(id_token)
    }
}
