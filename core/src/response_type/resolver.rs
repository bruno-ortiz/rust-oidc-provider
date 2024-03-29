use std::collections::HashMap;

use anyhow::anyhow;
use async_trait::async_trait;
use indexmap::IndexMap;

use oidc_types::response_type::{
    ResponseType, CODE_FLOW, CODE_ID_TOKEN_FLOW, CODE_ID_TOKEN_TOKEN_FLOW, CODE_TOKEN_FLOW,
    ID_TOKEN_FLOW, ID_TOKEN_TOKEN_FLOW, TOKEN_FLOW,
};

use crate::configuration::OpenIDProviderConfiguration;
use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::response_type::resolver::code::CodeResolver;
use crate::response_type::resolver::code_id_token::CodeIdTokenResolver;
use crate::response_type::resolver::code_id_token_token::CodeIdTokenTokenResolver;
use crate::response_type::resolver::code_token::CodeTokenResolver;
use crate::response_type::resolver::id_token::IDTokenResolver;
use crate::response_type::resolver::id_token_token::IdTokenTokenResolver;
use crate::response_type::resolver::token::TokenResolver;
use crate::response_type::UrlEncodable;

mod code;
mod code_id_token;
mod code_id_token_token;
mod code_token;
mod id_token;
mod id_token_token;
mod token;

#[async_trait]
pub trait ResponseTypeResolver {
    type Output: UrlEncodable;
    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError>;
}

pub struct DynamicResponseTypeResolver {
    resolver_map: HashMap<ResponseType, Box<dyn ResolverWrapper + Send + Sync>>,
}

impl DynamicResponseTypeResolver {
    fn new() -> Self {
        DynamicResponseTypeResolver {
            resolver_map: HashMap::new(),
        }
    }

    pub fn push(
        &mut self,
        response_type: ResponseType,
        resolver: Box<dyn ResolverWrapper + Send + Sync>,
    ) {
        self.resolver_map.insert(response_type, resolver);
    }
}

#[async_trait]
impl ResponseTypeResolver for DynamicResponseTypeResolver {
    type Output = IndexMap<String, String>;

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let rt = &context.request.response_type;
        let resolver = self.resolver_map.get(rt).ok_or_else(|| {
            OpenIdError::server_error(anyhow!(
                "OpenId Server error, no resolver found for response type"
            ))
        })?;
        let response = resolver.resolve(context).await?;
        Ok(response)
    }
}
#[async_trait]
pub trait ResolverWrapper {
    async fn resolve(
        &self,
        context: &OpenIDContext,
    ) -> Result<IndexMap<String, String>, OpenIdError>;
}
#[async_trait]
impl<RT: ResponseTypeResolver + Sync> ResolverWrapper for RT {
    async fn resolve(
        &self,
        context: &OpenIDContext,
    ) -> Result<IndexMap<String, String>, OpenIdError> {
        let result = self.resolve(context).await?;
        Ok(result.params())
    }
}

impl From<&OpenIDProviderConfiguration> for DynamicResponseTypeResolver {
    fn from(configuration: &OpenIDProviderConfiguration) -> Self {
        let mut resolver = DynamicResponseTypeResolver::new();
        for rt in configuration.response_types_supported() {
            if *rt == *CODE_FLOW {
                resolver.push(rt.clone(), Box::new(CodeResolver))
            } else if *rt == *ID_TOKEN_FLOW {
                resolver.push(rt.clone(), Box::new(IDTokenResolver::new(None, None)))
            } else if *rt == *CODE_ID_TOKEN_FLOW {
                resolver.push(rt.clone(), Box::new(CodeIdTokenResolver))
            } else if *rt == *CODE_TOKEN_FLOW {
                resolver.push(rt.clone(), Box::new(CodeTokenResolver))
            } else if *rt == *CODE_ID_TOKEN_TOKEN_FLOW {
                resolver.push(rt.clone(), Box::new(CodeIdTokenTokenResolver))
            } else if *rt == *ID_TOKEN_TOKEN_FLOW {
                resolver.push(rt.clone(), Box::new(IdTokenTokenResolver))
            } else if *rt == *TOKEN_FLOW {
                resolver.push(rt.clone(), Box::new(TokenResolver))
            } else {
                panic!("unsupported response type {}", rt)
            }
        }
        resolver
    }
}

#[cfg(test)]
mod tests {
    use oidc_types::nonce::Nonce;
    use oidc_types::response_type;
    use oidc_types::response_type::ResponseTypeValue::Code;
    use oidc_types::response_type::ResponseTypeValue::IdToken;
    use std::sync::Arc;

    use crate::context::test_utils::{setup_context, setup_provider};
    use crate::response_type::resolver::{DynamicResponseTypeResolver, ResponseTypeResolver};
    use crate::services::keystore::KeystoreService;

    #[tokio::test]
    async fn can_resolve_resolve_response_type_code() {
        let provider = Arc::new(setup_provider());
        let keystore_service = Arc::new(KeystoreService::new(provider.clone()));
        let context = setup_context(
            &provider,
            keystore_service,
            response_type!(Code),
            None,
            None,
        )
        .await;
        let resolver = DynamicResponseTypeResolver::from(provider.as_ref());
        let result = ResponseTypeResolver::resolve(&resolver, &context)
            .await
            .expect("Expected Ok value");

        assert!(result.contains_key("code"));
    }

    #[tokio::test]
    async fn can_resolve_resolve_response_type_code_id_token() {
        let provider = Arc::new(setup_provider());
        let keystore_service = Arc::new(KeystoreService::new(provider.clone()));
        let context = setup_context(
            &provider,
            keystore_service,
            response_type!(Code, IdToken),
            None,
            Some(Nonce::new("some-nonce")),
        )
        .await;
        let resolver = DynamicResponseTypeResolver::from(provider.as_ref());
        let result = ResponseTypeResolver::resolve(&resolver, &context)
            .await
            .expect("Expected Ok value");

        assert!(result.contains_key("code"));
        assert!(result.contains_key("id_token"));
    }
}
