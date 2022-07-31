use crate::adapter::Adapter;
use async_trait::async_trait;
use oidc_types::access_token::AccessToken;
use std::sync::Arc;

use crate::context::OpenIDContext;
use crate::id_token::IdToken;
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::code::CodeResolver;
use crate::response_type::resolver::id_token::IDTokenResolver;
use crate::response_type::resolver::token::TokenResolver;
use crate::response_type::resolver::ResponseTypeResolver;
use oidc_types::authorisation_code::AuthorisationCode;

pub struct CodeIdTokenTokenResolver {
    code_resolver: CodeResolver,
    token_resolver: TokenResolver,
}

impl CodeIdTokenTokenResolver {
    pub fn new(
        code_adapter: Arc<dyn Adapter<Item = AuthorisationCode, Id = String> + Send + Sync>,
        token_adapter: Arc<dyn Adapter<Item = AccessToken, Id = String> + Send + Sync>,
    ) -> Self {
        Self {
            code_resolver: CodeResolver::new(code_adapter),
            token_resolver: TokenResolver::new(token_adapter),
        }
    }
}

#[async_trait]
impl ResponseTypeResolver for CodeIdTokenTokenResolver {
    type Output = (AuthorisationCode, IdToken, AccessToken);

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let code = self.code_resolver.resolve(context);
        let token = self.token_resolver.resolve(context);

        let (code, token) = tokio::try_join!(code, token)?;

        let id_token_resolver = IDTokenResolver::new(Some(&code), Some(&token));
        let id_token = id_token_resolver.resolve(context).await?;

        Ok((code, id_token, token))
    }
}
