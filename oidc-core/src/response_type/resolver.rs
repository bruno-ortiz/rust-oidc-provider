use std::collections::HashMap;
use std::process::Output;

use oidc_types::authentication_request::AuthenticationRequest;
use oidc_types::jose::jwt::JWT;
use oidc_types::response_type::{ResponseType, ResponseTypeValue};

use crate::authorisation_code::AuthorisationCode;
use crate::id_token::IDToken;
use crate::response_type::authorisation_response::AuthorisationResponse;
use crate::state::State;

trait ResponseTypeResolver {
    fn resolve(&self, request: &AuthenticationRequest) -> AuthorisationResponse;
}

struct CodeResolver;

impl ResponseTypeResolver for CodeResolver {
    fn resolve(&self, request: &AuthenticationRequest) -> AuthorisationResponse {
        todo!()
    }
}

struct CodeIDTokenResolver;

impl ResponseTypeResolver for CodeIDTokenResolver {
    fn resolve(&self, request: &AuthenticationRequest) -> AuthorisationResponse {
        todo!()
    }
}

struct DynamicResponseTypeResolver {
    resolvers: HashMap<String, Box<dyn ResponseTypeResolver>>,
}

impl DynamicResponseTypeResolver {
    fn new() -> Self {
        DynamicResponseTypeResolver {
            resolvers: HashMap::new()
        }
    }

    fn add_resolver<RT: ResponseTypeResolver + 'static>(&mut self, response_type: ResponseType, resolver: RT) {
        self.resolvers.insert(response_type.to_string(), Box::new(resolver));
    }

    fn resolve(&self, request: &AuthenticationRequest) -> AuthorisationResponse {
        if let Some(rt) = &request.response_type {
            if let Some(resolver) = self.resolvers.get(&rt.to_string()) {
                resolver.resolve(request)
            } else { todo!("fix error treatment") }
        } else { todo!("fix error treatment") }
    }
}

#[cfg(test)]
mod tests {
    use oidc_types::authentication_request::AuthenticationRequest;
    use oidc_types::response_type;
    use oidc_types::response_type::ResponseTypeValue::{Code, IdToken};

    use crate::response_type::resolver::{CodeIDTokenResolver, CodeResolver, DynamicResponseTypeResolver};

    #[test]
    fn can_resolve_req() {
        let mut resolver = DynamicResponseTypeResolver::new();
        resolver.add_resolver(response_type!(Code), CodeResolver);
        resolver.add_resolver(response_type!(Code, IdToken), CodeIDTokenResolver);
    }
}
