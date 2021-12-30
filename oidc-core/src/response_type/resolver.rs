use std::collections::HashMap;

use chrono::Utc;
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;

use oidc_types::jose::jwt::JWT;
use oidc_types::response_type;
use oidc_types::response_type::{ResponseType, ResponseTypeValue};
use AuthorisationError::ResponseTypeResolveNotConfigured;

use crate::access_token::AccessToken;
use crate::authentication_request::AuthenticationRequest;
use crate::authorisation_code::AuthorisationCode;
use crate::configuration::OpenIDProviderConfiguration;
use crate::context::OpenIDContext;
use crate::hash::TokenHasher;
use crate::id_token::IdToken;
use crate::response_type::authorisation_response::AuthorisationResponse;
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
    fn resolve(&self, context: &OpenIDContext)
        -> Result<AuthorisationResponse, AuthorisationError>;
}

pub struct DynamicResponseTypeResolver {
    resolver_map: HashMap<ResponseType, Box<dyn ResponseTypeResolver>>,
}

impl DynamicResponseTypeResolver {
    fn new() -> Self {
        DynamicResponseTypeResolver {
            resolver_map: HashMap::new(),
        }
    }

    pub fn push<T>(&mut self, response_type: ResponseType, resolver: T)
    where
        T: ResponseTypeResolver + 'static,
    {
        self.resolver_map.insert(response_type, Box::new(resolver));
    }
}

impl ResponseTypeResolver for DynamicResponseTypeResolver {
    fn resolve(
        &self,
        context: &OpenIDContext,
    ) -> Result<AuthorisationResponse, AuthorisationError> {
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

impl From<OpenIDProviderConfiguration> for DynamicResponseTypeResolver {
    fn from(configuration: OpenIDProviderConfiguration) -> Self {
        let mut resolver = DynamicResponseTypeResolver::new();
        for rt in configuration.response_types() {
            if *rt == response_type![ResponseTypeValue::Code] {
                resolver.push(rt.clone(), CodeResolver)
            } else if *rt == response_type![ResponseTypeValue::IdToken] {
                resolver.push(rt.clone(), IDTokenResolver::new(None, None))
            } else if *rt == response_type![ResponseTypeValue::Code, ResponseTypeValue::IdToken] {
                resolver.push(rt.clone(), CodeIdTokenResolver)
            } else {
                panic!("unsupported response type {}", rt)
            }
        }
        resolver
    }
}

#[cfg(test)]
mod tests {
    use oidc_types::response_type;
    use oidc_types::response_type::ResponseTypeValue::{Code, IdToken};

    use crate::configuration::OpenIDProviderConfiguration;
    use crate::response_type::resolver::DynamicResponseTypeResolver;

    #[test]
    fn can_create_resolver_from_config() {
        let cfg = OpenIDProviderConfiguration::default();
        let resolver = DynamicResponseTypeResolver::from(cfg);
        println!("xpto")
    }
}
