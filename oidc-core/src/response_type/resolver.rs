use std::collections::HashMap;

use anyhow::anyhow;
use async_trait::async_trait;

use oidc_types::response_type;
use oidc_types::response_type::{ResponseType, ResponseTypeValue};

use crate::configuration::OpenIDProviderConfiguration;
use crate::context::OpenIDContext;
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::code::CodeResolver;
use crate::response_type::resolver::code_id_token::CodeIdTokenResolver;
use crate::response_type::resolver::id_token::IDTokenResolver;
use crate::response_type::UrlEncodable;

mod code;
mod code_id_token;
mod id_token;

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
    type Output = HashMap<String, String>;

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let rt = &context.request.response_type;
        let resolver = self.resolver_map.get(rt).ok_or(OpenIdError::ServerError {
            source: anyhow!("OpenId Server error, no resolver found for response type"),
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
    ) -> Result<HashMap<String, String>, OpenIdError>;
}
#[async_trait]
impl<RT: ResponseTypeResolver + Sync> ResolverWrapper for RT {
    async fn resolve(
        &self,
        context: &OpenIDContext,
    ) -> Result<HashMap<String, String>, OpenIdError> {
        let result = self.resolve(context).await?;
        Ok(result.params())
    }
}

impl From<OpenIDProviderConfiguration> for DynamicResponseTypeResolver {
    fn from(configuration: OpenIDProviderConfiguration) -> Self {
        let mut resolver = DynamicResponseTypeResolver::new();
        for rt in configuration.response_types() {
            if *rt == response_type![ResponseTypeValue::Code] {
                resolver.push(rt.clone(), Box::new(CodeResolver))
            } else if *rt == response_type![ResponseTypeValue::IdToken] {
                resolver.push(rt.clone(), Box::new(IDTokenResolver::new(None, None)))
            } else if *rt == response_type![ResponseTypeValue::Code, ResponseTypeValue::IdToken] {
                resolver.push(rt.clone(), Box::new(CodeIdTokenResolver))
            } else {
                panic!("unsupported response type {}", rt)
            }
        }
        resolver
    }
}

#[cfg(test)]
mod tests {
    use crate::configuration::OpenIDProviderConfiguration;
    use crate::response_type::resolver::DynamicResponseTypeResolver;

    #[test]
    fn can_create_resolver_from_config() {
        let cfg = OpenIDProviderConfiguration::default();
        let _resolver = DynamicResponseTypeResolver::from(cfg);
        println!("xpto")
    }
}
