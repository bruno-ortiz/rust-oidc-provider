use std::fmt::Debug;
use std::sync::Arc;

use derive_builder::Builder;
use futures::future::BoxFuture;
use getset::{CopyGetters, Getters};
use josekit::jwe::enc::{A128CBC_HS256, A128GCM, A256CBC_HS512, A256GCM};
use josekit::jwe::{Dir, A128KW, A256KW, ECDH_ES, RSA_OAEP};
use josekit::jws::{EdDSA, ES256, PS256, RS256};
use once_cell::sync::OnceCell;
use time::Duration;
use tracing::warn;
use url::Url;

use oidc_types::auth_method::AuthMethod;
use oidc_types::claim_type::ClaimType;
use oidc_types::grant_type::GrantType;
use oidc_types::issuer::Issuer;
use oidc_types::jose::jwe::alg::EncryptionAlgorithm;
use oidc_types::jose::jwe::enc::ContentEncryptionAlgorithm;
use oidc_types::jose::jws::SigningAlgorithm;
use oidc_types::password_hasher::HasherConfig;
use oidc_types::response_mode::ResponseMode;
use oidc_types::response_type::ResponseType;
use oidc_types::response_type::ResponseTypeValue::{Code, IdToken};
use oidc_types::scopes::Scopes;
use oidc_types::subject_type::SubjectType;
use oidc_types::{response_type, scopes};

use crate::configuration::adapter_container::AdapterContainer;
use crate::configuration::claims::ClaimsSupported;
use crate::configuration::clock::ClockProvider;
use crate::configuration::credentials::ClientCredentialConfiguration;
use crate::configuration::pkce::PKCE;
use crate::configuration::request_object::RequestObjectConfiguration;
use crate::configuration::routes::Routes;
use crate::configuration::ttl::TTL;
use crate::error::OpenIdError;
use crate::grant_type::RTContext;
use crate::keystore::KeyStore;
use crate::models::client::AuthenticatedClient;
use crate::profile::{NoOpProfileResolver, ProfileResolver};
use crate::services::types::Interaction;

static INSTANCE: OnceCell<OpenIDProviderConfiguration> = OnceCell::new();

const ONE_YEAR: Duration = Duration::days(365);
const DEFAULT_ISSUER: &str = "http://localhost:3000";
const DEFAULT_LOGIN_PATH: &str = "/interaction/login";
const DEFAULT_CONSENT_PATH: &str = "/interaction/consent";
type IssueRTFunc = Box<dyn Fn(&AuthenticatedClient) -> BoxFuture<bool> + Send + Sync>;
type RotateRefreshTokenFunc = Box<dyn Fn(RTContext<'_>) -> bool + Send + Sync>;
type ValidateRefreshTokenFunc =
    Box<dyn Fn(RTContext<'_>) -> BoxFuture<Result<(), OpenIdError>> + Send + Sync>;
type InteractionUrlResolver = Box<dyn Fn(Interaction) -> Url + Send + Sync>;

#[derive(Builder, CopyGetters, Getters)]
#[get = "pub"]
#[builder(pattern = "owned", setter(into, strip_option), default)]
pub struct OpenIDProviderConfiguration {
    pkce: PKCE,
    #[getset(skip)]
    keystore: Arc<KeyStore>,
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
    interaction_url_resolver: InteractionUrlResolver,
    subject_types_supported: Vec<SubjectType>, //TODO: create subject type resolvers
    #[getset(skip)]
    #[get_copy = "pub"]
    auth_max_age: u64,
    acr_values_supported: Option<Vec<String>>,
    authorization_signing_alg_values_supported: Option<Vec<SigningAlgorithm>>,
    authorization_encryption_alg_values_supported: Option<Vec<EncryptionAlgorithm>>,
    authorization_encryption_enc_values_supported: Option<Vec<ContentEncryptionAlgorithm>>,
    id_token_signing_alg_values_supported: Vec<SigningAlgorithm>,
    id_token_encryption_alg_values_supported: Option<Vec<EncryptionAlgorithm>>,
    id_token_encryption_enc_values_supported: Option<Vec<ContentEncryptionAlgorithm>>,
    userinfo_signing_alg_values_supported: Vec<SigningAlgorithm>,
    userinfo_encryption_alg_values_supported: Option<Vec<EncryptionAlgorithm>>,
    userinfo_encryption_enc_values_supported: Option<Vec<ContentEncryptionAlgorithm>>,
    request_object_signing_alg_values_supported: Vec<SigningAlgorithm>,
    request_object_encryption_alg_values_supported: Option<Vec<EncryptionAlgorithm>>,
    request_object_encryption_enc_values_supported: Option<Vec<ContentEncryptionAlgorithm>>,
    token_endpoint_auth_methods_supported: Vec<AuthMethod>,
    token_endpoint_auth_signing_alg_values_supported: Vec<SigningAlgorithm>,
    display_values_supported: Option<Vec<String>>,
    claim_types_supported: Option<Vec<ClaimType>>,
    claims_supported: ClaimsSupported,
    service_documentation: Option<String>,
    claims_locales_supported: Option<Vec<String>>,
    ui_locales_supported: Option<Vec<String>>,
    #[getset(skip)]
    #[get_copy = "pub"]
    claims_parameter_supported: bool,
    #[getset(skip)]
    #[get_copy = "pub"]
    secret_hasher: HasherConfig,
    client_credentials: ClientCredentialConfiguration,
    ttl: TTL,
    #[getset(skip)]
    issue_refresh_token: IssueRTFunc,
    #[getset(skip)]
    validate_refresh_token: ValidateRefreshTokenFunc,
    #[getset(skip)]
    rotate_refresh_token: RotateRefreshTokenFunc,
    #[builder(setter(custom))]
    profile_resolver: Box<dyn ProfileResolver + Send + Sync>,
    #[getset(skip)]
    #[get_copy = "pub"]
    enable_userinfo: bool,
    request_object: RequestObjectConfiguration,
    clock_provider: ClockProvider,
}

impl OpenIDProviderConfigurationBuilder {
    pub fn profile_resolver<T>(mut self, resolver: T) -> Self
    where
        T: ProfileResolver + Send + Sync + 'static,
    {
        self.profile_resolver = Some(Box::new(resolver));
        self
    }

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
    pub fn set(config: OpenIDProviderConfiguration) {
        if INSTANCE.set(config).is_err() {
            warn!("OpenIDProviderConfiguration.set should only be called once")
        };
    }

    pub fn instance() -> &'static OpenIDProviderConfiguration {
        INSTANCE.get_or_init(OpenIDProviderConfiguration::default)
    }

    pub fn clock() -> &'static ClockProvider {
        INSTANCE
            .get_or_init(OpenIDProviderConfiguration::default)
            .clock_provider()
    }

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

    pub async fn validate_refresh_token(&self, ctx: RTContext<'_>) -> Result<(), OpenIdError> {
        let func = &self.validate_refresh_token;
        func(ctx).await
    }

    pub fn rotate_refresh_token(&self, ctx: RTContext<'_>) -> bool {
        let func = &self.rotate_refresh_token;
        func(ctx)
    }

    pub async fn issue_refresh_token(&self, client: &AuthenticatedClient) -> bool {
        let func = &self.issue_refresh_token;
        func(client).await
    }

    pub fn keystore(&self) -> Arc<KeyStore> {
        self.keystore.clone()
    }
}

impl Default for OpenIDProviderConfiguration {
    fn default() -> Self {
        OpenIDProviderConfiguration {
            pkce: PKCE::default(),
            keystore: Arc::new(KeyStore::default()),
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
            interaction_url_resolver: Box::new(|interaction| {
                let configuration = OpenIDProviderConfiguration::instance();
                match interaction {
                    Interaction::Login { .. } => configuration.interaction_login_url(),
                    Interaction::Consent { .. } => configuration.interaction_consent_url(),
                    Interaction::None { .. } => {
                        panic!("Should not be called when interaction is None")
                    }
                }
            }),
            auth_max_age: 3600,
            subject_types_supported: vec![SubjectType::Public, SubjectType::Pairwise],
            claims_supported: ClaimsSupported::default(),
            acr_values_supported: None,
            authorization_signing_alg_values_supported: Some(vec![
                SigningAlgorithm::from(RS256),
                SigningAlgorithm::from(PS256),
                SigningAlgorithm::from(ES256),
                SigningAlgorithm::from(EdDSA),
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
                SigningAlgorithm::from(RS256),
                SigningAlgorithm::from(PS256),
                SigningAlgorithm::from(ES256),
                SigningAlgorithm::from(EdDSA),
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
                SigningAlgorithm::from(RS256),
                SigningAlgorithm::from(PS256),
                SigningAlgorithm::from(ES256),
                SigningAlgorithm::from(EdDSA),
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
                SigningAlgorithm::from(RS256),
                SigningAlgorithm::from(PS256),
                SigningAlgorithm::from(ES256),
                SigningAlgorithm::from(EdDSA),
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
            token_endpoint_auth_methods_supported: vec![
                AuthMethod::ClientSecretBasic,
                AuthMethod::ClientSecretPost,
            ],
            token_endpoint_auth_signing_alg_values_supported: vec![
                SigningAlgorithm::from(RS256),
                SigningAlgorithm::from(PS256),
                SigningAlgorithm::from(ES256),
                SigningAlgorithm::from(EdDSA),
            ],
            secret_hasher: HasherConfig::Sha256,
            client_credentials: ClientCredentialConfiguration::default(),
            ttl: TTL::default(),
            issue_refresh_token: Box::new(|c| {
                Box::pin(async { c.allows_grant(GrantType::RefreshToken) })
            }),
            rotate_refresh_token: Box::new(|ctx| {
                let RTContext { rt, client, .. } = ctx;
                if rt.total_lifetime() >= ONE_YEAR {
                    return false;
                }
                if client.auth_method() == AuthMethod::None {
                    return true;
                }
                rt.ttl_elapsed() >= 70.0
            }),
            validate_refresh_token: Box::new(|_ctx| Box::pin(async { Ok(()) })),
            display_values_supported: None,
            claim_types_supported: None,
            service_documentation: None,
            claims_locales_supported: None,
            ui_locales_supported: None,
            claims_parameter_supported: false,
            profile_resolver: Box::new(NoOpProfileResolver),
            enable_userinfo: false,
            request_object: Default::default(),
            clock_provider: Default::default(),
        }
    }
}
