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

pub struct CodeTokenResolver {
    code_resolver: CodeResolver,
}

impl CodeTokenResolver {
    pub fn new(
        adapter: Arc<dyn Adapter<Item = AuthorisationCode, Id = String> + Send + Sync>,
    ) -> Self {
        Self {
            code_resolver: CodeResolver::new(adapter),
        }
    }
}

#[async_trait]
impl ResponseTypeResolver for CodeTokenResolver {
    type Output = (AuthorisationCode, AccessToken);

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let code = self.code_resolver.resolve(context);
        let access_token = TokenResolver.resolve(context);

        let res = tokio::try_join!(code, access_token)?;
        Ok(res)
    }
}
