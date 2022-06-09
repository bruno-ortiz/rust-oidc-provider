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

pub struct CodeIdTokenTokenResolver {
    code_resolver: CodeResolver,
}

impl CodeIdTokenTokenResolver {
    pub fn new(
        adapter: Arc<dyn Adapter<Item = AuthorisationCode, Id = String> + Send + Sync>,
    ) -> Self {
        Self {
            code_resolver: CodeResolver::new(adapter),
        }
    }
}

#[async_trait]
impl ResponseTypeResolver for CodeIdTokenTokenResolver {
    type Output = (AuthorisationCode, IdToken, AccessToken);

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let code = self.code_resolver.resolve(context);
        let token = TokenResolver.resolve(context);

        let (code, token) = tokio::try_join!(code, token)?;

        let id_token_resolver = IDTokenResolver::new(Some(&code), Some(&token));
        let id_token = id_token_resolver.resolve(context).await?;

        Ok((code, id_token, token))
    }
}
