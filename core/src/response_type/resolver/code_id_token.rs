use async_trait::async_trait;

use oidc_types::code::Code;
use oidc_types::simple_id_token::SimpleIdToken;

use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::response_type::resolver::code::CodeResolver;
use crate::response_type::resolver::id_token::IDTokenResolver;
use crate::response_type::resolver::ResponseTypeResolver;

pub struct CodeIdTokenResolver;

#[async_trait]
impl ResponseTypeResolver for CodeIdTokenResolver {
    type Output = (Code, SimpleIdToken);

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let code = CodeResolver.resolve(context).await?;
        let id_token_resolver = IDTokenResolver::new(Some(&code), None);
        let id_token = id_token_resolver.resolve(context).await?;
        Ok((code, id_token))
    }
}
