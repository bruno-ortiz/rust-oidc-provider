use crate::adapter::Adapter;
use async_trait::async_trait;
use std::sync::Arc;

use crate::context::OpenIDContext;
use crate::id_token::IdToken;
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::code::CodeResolver;
use crate::response_type::resolver::id_token::IDTokenResolver;
use crate::response_type::resolver::ResponseTypeResolver;
use oidc_types::authorisation_code::AuthorisationCode;

pub struct CodeIdTokenResolver {
    code_resolver: CodeResolver,
}

impl CodeIdTokenResolver {
    pub fn new(
        adapter: Arc<dyn Adapter<Item = AuthorisationCode, Id = String> + Send + Sync>,
    ) -> Self {
        Self {
            code_resolver: CodeResolver::new(adapter),
        }
    }
}

#[async_trait]
impl ResponseTypeResolver for CodeIdTokenResolver {
    type Output = (AuthorisationCode, IdToken);

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let code = self.code_resolver.resolve(context).await?;
        let id_token_resolver = IDTokenResolver::new(Some(&code), None);
        let id_token = id_token_resolver.resolve(context).await?;
        Ok((code, id_token))
    }
}
