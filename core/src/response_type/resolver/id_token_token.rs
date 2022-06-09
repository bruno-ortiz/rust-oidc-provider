use crate::access_token::AccessToken;
use crate::adapter::Adapter;
use async_trait::async_trait;
use std::sync::Arc;

use crate::authorisation_code::AuthorisationCode;
use crate::context::OpenIDContext;
use crate::id_token::IdToken;
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::code::CodeResolver;
use crate::response_type::resolver::id_token::IDTokenResolver;
use crate::response_type::resolver::token::TokenResolver;
use crate::response_type::resolver::ResponseTypeResolver;

pub struct IdTokenTokenResolver;

#[async_trait]
impl ResponseTypeResolver for IdTokenTokenResolver {
    type Output = (IdToken, AccessToken);

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let access_token = TokenResolver.resolve(context).await?;
        let id_token_resolver = IDTokenResolver::new(None, Some(&access_token));
        let id_token = id_token_resolver.resolve(context).await?;

        Ok((id_token, access_token))
    }
}
