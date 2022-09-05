use async_trait::async_trait;

use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::models::access_token::AccessToken;
use crate::models::authorisation_code::AuthorisationCode;
use crate::response_type::resolver::code::CodeResolver;
use crate::response_type::resolver::id_token::IDTokenResolver;
use crate::response_type::resolver::token::TokenResolver;
use crate::response_type::resolver::ResponseTypeResolver;
use oidc_types::id_token::IdToken;

pub struct CodeIdTokenTokenResolver;

#[async_trait]
impl ResponseTypeResolver for CodeIdTokenTokenResolver {
    type Output = (AuthorisationCode, IdToken, AccessToken);

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let code = CodeResolver.resolve(context);
        let token = TokenResolver.resolve(context);

        let (code, token) = tokio::try_join!(code, token)?;

        let id_token_resolver = IDTokenResolver::new(Some(&code), Some(&token));
        let id_token = id_token_resolver.resolve(context).await?;

        Ok((code, id_token, token))
    }
}
