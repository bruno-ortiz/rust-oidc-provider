use std::sync::Arc;

use oidc_types::client::ClientInformation;
use oidc_types::response_type::Flow;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::OpenIDProviderConfiguration;
use crate::session::AuthenticatedUser;

pub struct OpenIDContext {
    pub client: Arc<ClientInformation>,
    pub user: AuthenticatedUser,
    pub request: ValidatedAuthorisationRequest,
    pub configuration: Arc<OpenIDProviderConfiguration>,
}

impl OpenIDContext {
    pub fn new(
        client: Arc<ClientInformation>,
        user: AuthenticatedUser,
        request: ValidatedAuthorisationRequest,
        configuration: Arc<OpenIDProviderConfiguration>,
    ) -> Self {
        OpenIDContext {
            client,
            user,
            request,
            configuration,
        }
    }

    pub fn flow_type(&self) -> Flow {
        self.request.response_type.flow()
    }
}

#[cfg(test)]
pub mod test_utils {
    use crate::authorisation_request::ValidatedAuthorisationRequest;
    use crate::configuration::OpenIDProviderConfiguration;
    use crate::context::OpenIDContext;
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

    pub fn setup_context(
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
