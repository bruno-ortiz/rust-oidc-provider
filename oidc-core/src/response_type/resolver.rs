use std::collections::HashMap;

use oidc_types::response_type;
use oidc_types::response_type::{ResponseType, ResponseTypeValue};
use AuthorisationError::ResponseTypeResolveNotConfigured;

use crate::configuration::OpenIDProviderConfiguration;
use crate::context::OpenIDContext;

use crate::response_type::errors::AuthorisationError;
use crate::response_type::errors::AuthorisationError::ResponseTypeNotAllowed;
use crate::response_type::resolver::code::CodeResolver;
use crate::response_type::resolver::code_id_token::CodeIdTokenResolver;
use crate::response_type::resolver::id_token::IDTokenResolver;
use crate::response_type::UrlEncodable;

mod code;
mod code_id_token;
mod id_token;

pub trait ResponseTypeResolver {
    type Output: UrlEncodable;
    fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, AuthorisationError>;
}

pub struct DynamicResponseTypeResolver {
    resolver_map: HashMap<ResponseType, Box<dyn ResolverWrapper>>,
}

impl DynamicResponseTypeResolver {
    fn new() -> Self {
        DynamicResponseTypeResolver {
            resolver_map: HashMap::new(),
        }
    }

    pub fn push(&mut self, response_type: ResponseType, resolver: Box<dyn ResolverWrapper>) {
        self.resolver_map.insert(response_type, resolver);
    }
}

impl ResponseTypeResolver for DynamicResponseTypeResolver {
    type Output = HashMap<String, String>;

    fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, AuthorisationError> {
        if let Some(rt) = &context.request.response_type {
            if !context.allows_response_type(rt) {
                return Err(ResponseTypeNotAllowed(
                    rt.clone(),
                    context.client.id.to_string(),
                ));
            }
            let resolver = self
                .resolver_map
                .get(rt)
                .ok_or(ResponseTypeResolveNotConfigured(rt.clone()))?;
            let response = resolver.resolve(context)?;
            Ok(response)
        } else {
            Err(AuthorisationError::MissingResponseType)
        }
    }
}

pub trait ResolverWrapper {
    fn resolve(
        &self,
        context: &OpenIDContext,
    ) -> Result<HashMap<String, String>, AuthorisationError>;
}

impl<RT: ResponseTypeResolver> ResolverWrapper for RT {
    fn resolve(
        &self,
        context: &OpenIDContext,
    ) -> Result<HashMap<String, String>, AuthorisationError> {
        let result = self.resolve(context)?;
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

impl UrlEncodable for HashMap<String, String> {
    fn params(&self) -> HashMap<String, String> {
        self.clone()
    }
}

impl<T1, T2> UrlEncodable for (T1, T2)
where
    T1: UrlEncodable,
    T2: UrlEncodable,
{
    fn params(&self) -> HashMap<String, String> {
        let mut first = self.0.params();
        let second = self.1.params();
        first.extend(second);
        first
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
