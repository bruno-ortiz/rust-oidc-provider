use std::sync::Arc;

use oidc_types::response_type::Flow;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::OpenIDProviderConfiguration;
use crate::models::client::ClientInformation;
use crate::models::grant::Grant;
use crate::services::keystore::KeystoreService;
use crate::user::AuthenticatedUser;

pub struct OpenIDContext<'a> {
    pub client: Arc<ClientInformation>,
    pub user: AuthenticatedUser,
    pub request: ValidatedAuthorisationRequest,
    pub grant: Grant,
    pub provider: &'a OpenIDProviderConfiguration,
    pub keystore_service: Arc<KeystoreService>,
}

impl<'a> OpenIDContext<'a> {
    pub fn new(
        client: Arc<ClientInformation>,
        user: AuthenticatedUser,
        request: ValidatedAuthorisationRequest,
        grant: Grant,
        provider: &'a OpenIDProviderConfiguration,
        keystore_service: Arc<KeystoreService>,
    ) -> Self {
        OpenIDContext {
            client,
            user,
            request,
            grant,
            provider,
            keystore_service,
        }
    }

    pub fn flow_type(&self) -> Flow {
        self.request.response_type.flow()
    }
}

#[cfg(test)]
pub mod test_utils {
    use std::collections::HashSet;
    use std::sync::Arc;

    use josekit::jwk::alg::ec::EcCurve;
    use josekit::jwk::Jwk;
    use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm;
    use josekit::jws::ES256;
    use time::OffsetDateTime;
    use url::Url;
    use uuid::Uuid;

    use oidc_types::application_type::ApplicationType;
    use oidc_types::auth_method::AuthMethod;
    use oidc_types::claims::Claims;
    use oidc_types::client::{ClientID, ClientMetadata};
    use oidc_types::jose::jwk_set::JwkSet;
    use oidc_types::nonce::Nonce;
    use oidc_types::password_hasher::HasherConfig;
    use oidc_types::pkce::{CodeChallenge, CodeChallengeMethod};
    use oidc_types::response_type::ResponseType;
    use oidc_types::response_type::ResponseTypeValue::Code;
    use oidc_types::response_type::ResponseTypeValue::IdToken;
    use oidc_types::response_type::ResponseTypeValue::Token;
    use oidc_types::secret::HashedSecret;
    use oidc_types::state::State;
    use oidc_types::subject::Subject;
    use oidc_types::subject_type::SubjectType;
    use oidc_types::{response_type, scopes};

    use crate::authorisation_request::ValidatedAuthorisationRequest;
    use crate::client::register_client;
    use crate::configuration::{OpenIDProviderConfiguration, OpenIDProviderConfigurationBuilder};
    use crate::context::OpenIDContext;
    use crate::keystore::KeyStore;
    use crate::models::client::ClientInformation;
    use crate::models::grant::GrantBuilder;
    use crate::session::SessionID;
    use crate::user::AuthenticatedUser;

    //noinspection DuplicatedCode
    pub async fn setup_context(
        provider: &OpenIDProviderConfiguration,
        response_type: ResponseType,
        state: Option<State>,
        nonce: Option<Nonce>,
    ) -> OpenIDContext<'_> {
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
            prompt: None,
            acr_values: None,
            claims: None,
            max_age: None,
            id_token_hint: None,
            login_hint: None,
        };
        let (hashed, _) = HashedSecret::random(HasherConfig::Sha256).unwrap();
        let metadata = ClientMetadata {
            redirect_uris: vec![],
            token_endpoint_auth_method: AuthMethod::None,
            token_endpoint_auth_signing_alg: None,
            default_max_age: None,
            require_auth_time: false,
            default_acr_values: None,
            initiate_login_uri: None,
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
            sector_identifier_uri: None,
            subject_type: SubjectType::Public,
            id_token_signed_response_alg: ES256.into(),
            userinfo_signed_response_alg: None,
            request_object_signing_alg: None,
            software_version: None,
            software_statement: None,
            application_type: ApplicationType::Native,
            authorization_signed_response_alg: ES256.into(),
            request_uris: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            software_id: None,
        };

        let client =
            ClientInformation::new(client_id, OffsetDateTime::now_utc(), hashed, None, metadata);

        let user = AuthenticatedUser::new(
            SessionID::default(),
            Subject::new("some-id"),
            OffsetDateTime::now_utc(),
            Uuid::new_v4(),
            None,
            None,
        );

        register_client(provider, client.clone()).await.unwrap();

        let grant = GrantBuilder::new()
            .subject(user.sub().clone())
            .scopes(scopes!("openid", "test"))
            .acr(user.acr().clone())
            .amr(user.amr().cloned())
            .client_id(request.client_id)
            .auth_time(user.auth_time())
            .max_age(request.max_age)
            .redirect_uri(request.redirect_uri.clone())
            .rejected_claims(HashSet::new())
            .claims(Claims::default())
            .build()
            .expect("Should always build successfully");

        let grant = provider
            .adapter()
            .grant()
            .insert(grant, None)
            .await
            .unwrap();
        let user = user.with_grant(grant.id()).save(provider).await.unwrap();
        OpenIDContext::new(Arc::new(client), user, request, grant, provider)
    }

    pub fn setup_provider() -> OpenIDProviderConfiguration {
        let mut jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        jwk.set_algorithm(EcdsaJwsAlgorithm::Es256.to_string());
        jwk.set_key_id("test-key-id");
        jwk.set_key_use("sig");
        OpenIDProviderConfigurationBuilder::default()
            .issuer("https://oidc.rs.com")
            .keystore(KeyStore::new(JwkSet::new(vec![jwk])))
            .response_types_supported(vec![
                response_type![Code],
                response_type![IdToken],
                response_type![Token],
                response_type![Code, IdToken],
                response_type![Code, Token],
                response_type![Code, IdToken, Token],
                response_type![IdToken, Token],
            ])
            .build()
            .unwrap()
    }
}
