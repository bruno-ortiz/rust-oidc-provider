use std::collections::HashMap;

use anyhow::anyhow;
use async_trait::async_trait;
use indexmap::IndexMap;

use oidc_types::response_type;
use oidc_types::response_type::{
    ResponseType, ResponseTypeValue, CODE_FLOW, CODE_ID_TOKEN_FLOW, CODE_ID_TOKEN_TOKEN_FLOW,
    CODE_TOKEN_FLOW, ID_TOKEN_FLOW, ID_TOKEN_TOKEN_FLOW, TOKEN_FLOW,
};

use crate::configuration::OpenIDProviderConfiguration;
use crate::context::OpenIDContext;
use crate::response_type::errors::OpenIdError;
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
        let code_adapter = configuration.adapters().code();
        let mut resolver = DynamicResponseTypeResolver::new();
        for rt in configuration.response_types() {
            if *rt == *CODE_FLOW {
                resolver.push(
                    rt.clone(),
                    Box::new(CodeResolver::new(code_adapter.clone())),
                )
            } else if *rt == *ID_TOKEN_FLOW {
                resolver.push(rt.clone(), Box::new(IDTokenResolver::new(None, None)))
            } else if *rt == *CODE_ID_TOKEN_FLOW {
                resolver.push(
                    rt.clone(),
                    Box::new(CodeIdTokenResolver::new(code_adapter.clone())),
                )
            } else if *rt == *CODE_TOKEN_FLOW {
                resolver.push(
                    rt.clone(),
                    Box::new(CodeTokenResolver::new(code_adapter.clone())),
                )
            } else if *rt == *CODE_ID_TOKEN_TOKEN_FLOW {
                resolver.push(
                    rt.clone(),
                    Box::new(CodeIdTokenTokenResolver::new(code_adapter.clone())),
                )
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
    use crate::authorisation_request::ValidatedAuthorisationRequest;
    use crate::configuration::OpenIDProviderConfiguration;
    use crate::context::OpenIDContext;
    use crate::response_type::resolver::{
        DynamicResponseTypeResolver, ResolverWrapper, ResponseTypeResolver,
    };
    use crate::session::{AuthenticatedUser, SessionID};
    use josekit::jwk::alg::ec::EcCurve;
    use josekit::jwk::Jwk;
    use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm;
    use oidc_types::client::{ClientID, ClientInformation, ClientMetadata};
    use oidc_types::jose::jwk_set::JwkSet;
    use oidc_types::nonce::Nonce;
    use oidc_types::pkce::{CodeChallenge, CodeChallengeMethod};
    use oidc_types::response_type::ResponseType;
    use oidc_types::response_type::ResponseTypeValue::Code;
    use oidc_types::response_type::ResponseTypeValue::IdToken;
    use oidc_types::response_type::ResponseTypeValue::Token;
    use oidc_types::state::State;
    use oidc_types::subject::Subject;
    use oidc_types::{response_type, scopes};
    use std::sync::Arc;
    use time::OffsetDateTime;
    use url::Url;
    use uuid::Uuid;

    #[tokio::test]
    async fn can_resolve_resolve_response_type_code() {
        let context = setup_context(response_type!(Code), None, None);
        let resolver = DynamicResponseTypeResolver::from(context.configuration.as_ref());
        let result = ResponseTypeResolver::resolve(&resolver, &context)
            .await
            .expect("Expected Ok value");

        assert!(result.contains_key("code"));
    }

    #[tokio::test]
    async fn can_resolve_resolve_response_type_code_id_token() {
        let context = setup_context(
            response_type!(Code, IdToken),
            None,
            Some(Nonce::new("some-nonce")),
        );
        let resolver = DynamicResponseTypeResolver::from(context.configuration.as_ref());
        let result = ResponseTypeResolver::resolve(&resolver, &context)
            .await
            .expect("Expected Ok value");

        assert!(result.contains_key("code"));
        assert!(result.contains_key("id_token"));
    }

    //noinspection DuplicatedCode
    fn setup_context(
        response_type: ResponseType,
        state: Option<State>,
        nonce: Option<Nonce>,
    ) -> OpenIDContext {
        let client_id = ClientID::new(Uuid::new_v4());
        let request = ValidatedAuthorisationRequest {
            client_id,
            response_type,
            redirect_uri: Url::parse("https://test.com/callback").unwrap(),
            scope: scopes!("openid", "test"),
            state,
            nonce,
            response_mode: None,
            code_challenge: Some(CodeChallenge::new("some code here")),
            code_challenge_method: Some(CodeChallengeMethod::Plain),
            resource: None,
            include_granted_scopes: None,
            request_uri: None,
            request: None,
            prompt: None,
        };
        let client = ClientInformation {
            id: client_id,
            issue_date: OffsetDateTime::now_utc(),
            metadata: ClientMetadata {
                redirect_uris: vec![],
                token_endpoint_auth_method: None,
                grant_types: vec![],
                response_types: vec![],
                scope: scopes!("openid", "test"),
                client_name: None,
                client_uri: None,
                logo_uri: None,
                tos_uri: None,
                policy_uri: None,
                contacts: vec![],
                jwks_uri: None,
                jwks: None,
                software_id: None,
                software_version: None,
                software_statement: None,
            },
        };

        let user = AuthenticatedUser::new(
            SessionID::default(),
            Subject::new("some-id"),
            OffsetDateTime::now_utc(),
            120,
        );

        let mut jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        jwk.set_algorithm(EcdsaJwsAlgorithm::Es256.to_string());
        jwk.set_key_id("test-key-id");
        jwk.set_key_use("sig");
        let config = OpenIDProviderConfiguration::new("https://oidc.rs.com")
            .with_jwks(JwkSet::new(vec![jwk]))
            .with_response_types(vec![
                response_type![Code],
                response_type![IdToken],
                response_type![Token],
                response_type![Code, IdToken],
                response_type![Code, Token],
                response_type![Code, IdToken, Token],
                response_type![IdToken, Token],
            ]);
        OpenIDContext::new(Arc::new(client), user, request, Arc::new(config))
    }
}
