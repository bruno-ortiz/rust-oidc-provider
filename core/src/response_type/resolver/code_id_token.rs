use async_trait::async_trait;

use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::response_type::resolver::code::CodeResolver;
use crate::response_type::resolver::id_token::IDTokenResolver;
use crate::response_type::resolver::ResponseTypeResolver;
use oidc_types::authorisation_code::AuthorisationCode;
use oidc_types::id_token::IdToken;

pub struct CodeIdTokenResolver;

#[async_trait]
impl ResponseTypeResolver for CodeIdTokenResolver {
    type Output = (AuthorisationCode, IdToken);

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let code = CodeResolver.resolve(context).await?;
        let id_token_resolver = IDTokenResolver::new(Some(&code), None);
        let id_token = id_token_resolver.resolve(context).await?;
        Ok((code, id_token))
    }
}
