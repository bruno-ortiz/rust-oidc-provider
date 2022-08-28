use derive_builder::Builder;
use getset::{CopyGetters, Getters};
use josekit::jwe::enc::{A128CBC_HS256, A128GCM, A256CBC_HS512, A256GCM};
use josekit::jwe::{Dir, A128KW, A256KW, ECDH_ES, RSA_OAEP};
use std::fmt::Debug;

use josekit::jwk::Jwk;
use josekit::jws::{EdDSA, ES256, PS256, RS256};
use url::Url;

use oidc_types::auth_method::AuthMethod;
use oidc_types::claim_type::ClaimType;
use oidc_types::grant_type::GrantType;
use oidc_types::issuer::Issuer;
use oidc_types::jose::jwe::alg::EncryptionAlgorithm;
use oidc_types::jose::jwe::enc::ContentEncryptionAlgorithm;
use oidc_types::jose::jwk_set::JwkSet;
use oidc_types::jose::jws::Algorithm;
use oidc_types::password_hasher::HasherConfig;
use oidc_types::response_mode::ResponseMode;
use oidc_types::response_type::ResponseType;
use oidc_types::response_type::ResponseTypeValue::{Code, IdToken};
use oidc_types::scopes::Scopes;
use oidc_types::subject_type::SubjectType;
use oidc_types::{response_type, scopes};

use crate::configuration::adapter_container::AdapterContainer;
use crate::configuration::credentials::ClientCredentialConfiguration;
use crate::configuration::pkce::PKCE;
use crate::configuration::routes::Routes;
use crate::services::types::Interaction;

const DEFAULT_ISSUER: &str = "http://localhost:3000";
const DEFAULT_LOGIN_PATH: &str = "/interaction/login/";
const DEFAULT_CONSENT_PATH: &str = "/interaction/consent/";

#[derive(Builder, CopyGetters, Getters)]
#[get = "pub"]
#[builder(pattern = "owned", setter(into, strip_option), default)]
pub struct OpenIDProviderConfiguration {
    pkce: PKCE,
    jwks: JwkSet,
    routes: Routes,
    adapters: AdapterContainer,
    response_types_supported: Vec<ResponseType>,
    #[builder(setter(custom))]
    response_modes_supported: Vec<ResponseMode>,
    #[builder(setter(custom))]
    #[getset(skip)]
    #[get_copy = "pub"]
    jwt_secure_response_mode: bool,
    issuer: Issuer,
    grant_types_supported: Vec<GrantType>,
    scopes_supported: Scopes,
    #[builder(setter(skip))]
    interaction_base_url: Box<dyn Fn(&Self) -> &Url + Send + Sync>,
    #[builder(setter(skip))]
    interaction_url_resolver: Box<dyn Fn(Interaction, &Self) -> Url + Send + Sync>,
    subject_types_supported: Vec<SubjectType>, //TODO: create subject type resolvers
    #[getset(skip)]
    #[get_copy = "pub"]
    auth_max_age: u64,
    acr_values_supported: Option<Vec<String>>,
    authorization_signing_alg_values_supported: Option<Vec<Algorithm>>,
    authorization_encryption_alg_values_supported: Option<Vec<EncryptionAlgorithm>>,
    authorization_encryption_enc_values_supported: Option<Vec<ContentEncryptionAlgorithm>>,
    id_token_signing_alg_values_supported: Vec<Algorithm>,
    id_token_encryption_alg_values_supported: Option<Vec<EncryptionAlgorithm>>,
    id_token_encryption_enc_values_supported: Option<Vec<ContentEncryptionAlgorithm>>,
    userinfo_signing_alg_values_supported: Vec<Algorithm>,
    userinfo_encryption_alg_values_supported: Option<Vec<EncryptionAlgorithm>>,
    userinfo_encryption_enc_values_supported: Option<Vec<ContentEncryptionAlgorithm>>,
    request_object_signing_alg_values_supported: Vec<Algorithm>,
    request_object_encryption_alg_values_supported: Option<Vec<EncryptionAlgorithm>>,
    request_object_encryption_enc_values_supported: Option<Vec<ContentEncryptionAlgorithm>>,
    token_endpoint_auth_methods_supported: Vec<AuthMethod>,
    token_endpoint_auth_signing_alg_values_supported: Vec<Algorithm>,
    display_values_supported: Option<Vec<String>>,
    claim_types_supported: Option<Vec<ClaimType>>,
    claims_supported: Vec<String>,
    service_documentation: Option<String>,
    claims_locales_supported: Option<Vec<String>>,
    ui_locales_supported: Option<Vec<String>>,
    #[getset(skip)]
    #[get_copy = "pub"]
    claims_parameter_supported: bool,
    #[getset(skip)]
    #[get_copy = "pub"]
    request_parameter_supported: bool,
    #[getset(skip)]
    #[get_copy = "pub"]
    request_uri_parameter_supported: bool,
    #[getset(skip)]
    #[get_copy = "pub"]
    require_request_uri_registration: bool,
    #[getset(skip)]
    #[get_copy = "pub"]
    secret_hasher: HasherConfig,
    client_credentials: ClientCredentialConfiguration,
}

impl OpenIDProviderConfigurationBuilder {
    pub fn enable_jarm(mut self) -> Self {
        self.jwt_secure_response_mode = Some(true);
        self.response_modes_supported = Some(vec![
            ResponseMode::Query,
            ResponseMode::Fragment,
            ResponseMode::Jwt,
            ResponseMode::QueryJwt,
            ResponseMode::FragmentJwt,
        ]);
        self
    }
}

impl OpenIDProviderConfiguration {
    pub fn interaction_login_url(&self) -> Url {
        let interaction_url_fn = &self.interaction_base_url;
        interaction_url_fn(self)
            .join(DEFAULT_LOGIN_PATH)
            .expect("Should return a valid url")
    }

    pub fn interaction_consent_url(&self) -> Url {
        let interaction_url_fn = &self.interaction_base_url;
        interaction_url_fn(self)
            .join(DEFAULT_CONSENT_PATH)
            .expect("Should return a valid url")
    }

    pub fn signing_key(&self) -> Option<&Jwk> {
        //todo: permit multiple signing keys, and let the resolver decide???
        self.jwks
            .iter()
            .find(|key| key.algorithm().is_some() && key.key_use() == Some("sig"))
    }
}

impl Default for OpenIDProviderConfiguration {
    fn default() -> Self {
        OpenIDProviderConfiguration {
            pkce: PKCE::default(),
            jwks: JwkSet::default(),
            routes: Routes::default(),
            adapters: AdapterContainer::default(),
            response_types_supported: vec![
                response_type![Code],
                response_type![IdToken],
                response_type![Code, IdToken],
            ],
            response_modes_supported: vec![ResponseMode::Query, ResponseMode::Fragment],
            jwt_secure_response_mode: false,
            issuer: Issuer::new(DEFAULT_ISSUER),
            scopes_supported: scopes!("openid"),
            grant_types_supported: vec![
                GrantType::AuthorizationCode,
                GrantType::ClientCredentials,
                GrantType::RefreshToken,
            ],
            interaction_base_url: Box::new(|config| config.issuer.inner()),
            interaction_url_resolver: Box::new(|interaction, config| match interaction {
                Interaction::Login { .. } => config.interaction_login_url(),
                Interaction::Consent { .. } => config.interaction_consent_url(),
                Interaction::None { .. } => panic!("Should not be called when interaction is None"),
            }),
            auth_max_age: 3600,
            subject_types_supported: vec![SubjectType::Public, SubjectType::Pairwise],
            claims_supported: vec![],
            acr_values_supported: None,
            authorization_signing_alg_values_supported: Some(vec![
                Algorithm::from(RS256),
                Algorithm::from(PS256),
                Algorithm::from(ES256),
                Algorithm::from(EdDSA),
            ]),
            authorization_encryption_alg_values_supported: Some(vec![
                A128KW.into(),
                A256KW.into(),
                ECDH_ES.into(),
                RSA_OAEP.into(),
                Dir.into(),
            ]),
            authorization_encryption_enc_values_supported: Some(vec![
                A128CBC_HS256.into(),
                A128GCM.into(),
                A256CBC_HS512.into(),
                A256GCM.into(),
            ]),
            id_token_signing_alg_values_supported: vec![
                Algorithm::from(RS256),
                Algorithm::from(PS256),
                Algorithm::from(ES256),
                Algorithm::from(EdDSA),
            ],
            id_token_encryption_alg_values_supported: Some(vec![
                A128KW.into(),
                A256KW.into(),
                ECDH_ES.into(),
                RSA_OAEP.into(),
                Dir.into(),
            ]),
            id_token_encryption_enc_values_supported: Some(vec![
                A128CBC_HS256.into(),
                A128GCM.into(),
                A256CBC_HS512.into(),
                A256GCM.into(),
            ]),
            userinfo_signing_alg_values_supported: vec![
                Algorithm::from(RS256),
                Algorithm::from(PS256),
                Algorithm::from(ES256),
                Algorithm::from(EdDSA),
            ],
            userinfo_encryption_alg_values_supported: Some(vec![
                A128KW.into(),
                A256KW.into(),
                ECDH_ES.into(),
                RSA_OAEP.into(),
                Dir.into(),
            ]),
            userinfo_encryption_enc_values_supported: Some(vec![
                A128CBC_HS256.into(),
                A128GCM.into(),
                A256CBC_HS512.into(),
                A256GCM.into(),
            ]),
            request_object_signing_alg_values_supported: vec![
                Algorithm::from(RS256),
                Algorithm::from(PS256),
                Algorithm::from(ES256),
                Algorithm::from(EdDSA),
            ],
            request_object_encryption_alg_values_supported: Some(vec![
                A128KW.into(),
                A256KW.into(),
                ECDH_ES.into(),
                RSA_OAEP.into(),
                Dir.into(),
            ]),
            request_object_encryption_enc_values_supported: Some(vec![
                A128CBC_HS256.into(),
                A128GCM.into(),
                A256CBC_HS512.into(),
                A256GCM.into(),
            ]),
            token_endpoint_auth_methods_supported: vec![AuthMethod::ClientSecretBasic],
            token_endpoint_auth_signing_alg_values_supported: vec![
                Algorithm::from(RS256),
                Algorithm::from(PS256),
                Algorithm::from(ES256),
                Algorithm::from(EdDSA),
            ],
            secret_hasher: HasherConfig::Sha256,
            client_credentials: ClientCredentialConfiguration::default(),
            display_values_supported: None,
            claim_types_supported: None,
            service_documentation: None,
            claims_locales_supported: None,
            ui_locales_supported: None,
            claims_parameter_supported: false,
            request_parameter_supported: false,
            request_uri_parameter_supported: true,
            require_request_uri_registration: false,
        }
    }
}
