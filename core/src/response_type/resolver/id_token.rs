use anyhow::anyhow;
use async_trait::async_trait;
use time::{Duration, OffsetDateTime};

use crate::access_token::AccessToken;
use crate::authorisation_code::AuthorisationCode;
use crate::context::OpenIDContext;
use crate::id_token::IdToken;
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::ResponseTypeResolver;

pub struct IDTokenResolver<'a> {
    code: Option<&'a AuthorisationCode>,
    token: Option<&'a AccessToken>,
}

impl<'a> IDTokenResolver<'a> {
    pub fn new(code: Option<&'a AuthorisationCode>, token: Option<&'a AccessToken>) -> Self {
        IDTokenResolver { code, token }
    }
}
#[async_trait]
impl ResponseTypeResolver for IDTokenResolver<'_> {
    type Output = IdToken;

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let signing_key = context
            .configuration
            .signing_key()
            .ok_or(OpenIdError::ServerError {
                source: anyhow!("Missing signing key"),
            })?;
        let id_token = IdToken::builder(signing_key)
            .with_issuer(context.configuration.issuer())
            .with_sub(context.user.sub())
            .with_audience(vec![context.client.id.into()])
            .with_exp(OffsetDateTime::now_utc() + Duration::hours(10)) //TODO: make duration configurable
            .with_iat(OffsetDateTime::now_utc())
            .with_s_hash(context.request.state.as_ref())?
            .with_c_hash(self.code)?
            .with_at_hash(self.token)?
            .with_auth_time(context.user.auth_time())
            .build()
            .map_err(|err| OpenIdError::ServerError { source: err.into() })?;
        Ok(id_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorisation_request::ValidatedAuthorisationRequest;
    use crate::configuration::OpenIDProviderConfiguration;
    use crate::session::{AuthenticatedUser, SessionID};
    use josekit::jwk::alg::ec::EcCurve;
    use josekit::jwk::Jwk;
    use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm;
    use oidc_types::client::{ClientID, ClientInformation, ClientMetadata};
    use oidc_types::jose::jwk_set::JwkSet;
    use oidc_types::pkce::{CodeChallenge, CodeChallengeMethod};
    use oidc_types::response_type::ResponseTypeValue;
    use oidc_types::subject::Subject;
    use oidc_types::{response_type, scopes};
    use std::sync::Arc;
    use time::OffsetDateTime;
    use url::Url;
    use uuid::Uuid;

    #[tokio::test]
    async fn can_generate_id_token() {
        let context = setup_context();
        let resolver = IDTokenResolver::new(None, None);

        let id_token = resolver
            .resolve(&context)
            .await
            .expect("Expecting a id token");

        println!("id token: {id_token:?}")
    }

    //noinspection DuplicatedCode
    fn setup_context() -> OpenIDContext {
        let client_id = ClientID::new(Uuid::new_v4());
        let request = ValidatedAuthorisationRequest {
            client_id,
            response_type: response_type![ResponseTypeValue::Code],
            redirect_uri: Url::parse("https://test.com/callback").unwrap(),
            scope: scopes!("openid", "test"),
            state: None,
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
            .with_jwks(JwkSet::new(vec![jwk]));
        OpenIDContext::new(Arc::new(client), user, request, Arc::new(config))
    }
}
