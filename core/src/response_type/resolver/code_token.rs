use async_trait::async_trait;

use oidc_types::code::Code;

use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::models::access_token::AccessToken;
use crate::response_type::resolver::code::CodeResolver;
use crate::response_type::resolver::token::TokenResolver;
use crate::response_type::resolver::ResponseTypeResolver;

pub struct CodeTokenResolver;

#[async_trait]
impl ResponseTypeResolver for CodeTokenResolver {
    type Output = (Code, AccessToken);

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let code = CodeResolver.resolve(context);
        let access_token = TokenResolver.resolve(context);

        let res = tokio::try_join!(code, access_token)?;
        Ok(res)
    }
}
