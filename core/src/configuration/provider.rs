use derive_builder::Builder;
use derive_getters::Getters;
use std::fmt::Debug;

use josekit::jwk::Jwk;
use josekit::jws::{EdDSA, ES256, PS256, RS256};
use url::Url;

use oidc_types::grant_type::GrantType;
use oidc_types::issuer::Issuer;
use oidc_types::jose::algorithm::Algorithm;
use oidc_types::jose::jwk_set::JwkSet;
use oidc_types::response_mode::ResponseMode;
use oidc_types::response_type::ResponseType;
use oidc_types::response_type::ResponseTypeValue::{Code, IdToken};
use oidc_types::scopes::Scopes;
use oidc_types::subject_type::SubjectType;
use oidc_types::{response_type, scopes};

use crate::configuration::adapter_container::AdapterContainer;
use crate::configuration::pkce::PKCE;
use crate::configuration::routes::Routes;
use crate::services::interaction::Interaction;

const DEFAULT_ISSUER: &str = "http://localhost:3000";

type InteractionFunction =
    Box<dyn Fn(&Interaction, &OpenIDProviderConfiguration) -> Url + Send + Sync>;

#[derive(Builder, Getters)]
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
    jwt_secure_response_mode: bool,
    issuer: Issuer,
    grant_types_supported: Vec<GrantType>,
    scopes_supported: Scopes,
    interaction_base_url: Url,
    #[getter(rename = "interaction_fn")]
    interaction_config: InteractionFunction,
    subject_types_supported: Vec<SubjectType>,
    acr_values_supported: Option<Vec<String>>,
    id_token_signing_alg_values_supported: Vec<Algorithm>,
    id_token_encryption_alg_values_supported: Option<Vec<String>>,
    id_token_encryption_enc_values_supported: Option<Vec<String>>,
    userinfo_signing_alg_values_supported: Vec<Algorithm>,
    userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    request_object_signing_alg_values_supported: Vec<Algorithm>,
    request_object_encryption_alg_values_supported: Option<Vec<String>>,
    request_object_encryption_enc_values_supported: Option<Vec<String>>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    token_endpoint_auth_signing_alg_values_supported: Vec<Algorithm>,
    display_values_supported: Option<Vec<String>>,
    claim_types_supported: Option<Vec<String>>,
    claims_supported: Option<Vec<String>>,
    service_documentation: Option<String>,
    claims_locales_supported: Option<Vec<String>>,
    ui_locales_supported: Option<Vec<String>>,
    claims_parameter_supported: Option<bool>,
    request_parameter_supported: Option<bool>,
    request_uri_parameter_supported: Option<bool>,
    require_request_uri_registration: Option<bool>,
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
            interaction_base_url: Url::parse(DEFAULT_ISSUER)
                .expect("Default issuer should be a valid url"),
            interaction_config: Box::new(|interaction, config| {
                let base_url = &config.interaction_base_url;
                let mut url = if interaction.user().is_none() {
                    base_url
                        .join("/interaction/login/")
                        .expect("Should return a valid url")
                } else {
                    base_url
                        .join("/interaction/consent/")
                        .expect("Should return a valid url")
                };
                url.query_pairs_mut()
                    .append_pair("interaction_id", &interaction.id().to_string());
                url
            }),
            subject_types_supported: vec![SubjectType::Public, SubjectType::Pairwise], //TODO: create subject type resolvers
            acr_values_supported: None,
            id_token_signing_alg_values_supported: vec![
                Algorithm::from(RS256),
                Algorithm::from(PS256),
                Algorithm::from(ES256),
                Algorithm::from(EdDSA),
            ],
            id_token_encryption_alg_values_supported: None,
            id_token_encryption_enc_values_supported: None,
            userinfo_signing_alg_values_supported: vec![
                Algorithm::from(RS256),
                Algorithm::from(PS256),
                Algorithm::from(ES256),
                Algorithm::from(EdDSA),
            ],
            userinfo_encryption_alg_values_supported: None,
            userinfo_encryption_enc_values_supported: None,
            request_object_signing_alg_values_supported: vec![
                Algorithm::from(RS256),
                Algorithm::from(PS256),
                Algorithm::from(ES256),
                Algorithm::from(EdDSA),
            ],
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            token_endpoint_auth_methods_supported: None,
            token_endpoint_auth_signing_alg_values_supported: vec![
                Algorithm::from(RS256),
                Algorithm::from(PS256),
                Algorithm::from(ES256),
                Algorithm::from(EdDSA),
            ],
            display_values_supported: None,
            claim_types_supported: None,
            claims_supported: None,
            service_documentation: None,
            claims_locales_supported: None,
            ui_locales_supported: None,
            claims_parameter_supported: None,
            request_parameter_supported: None,
            request_uri_parameter_supported: None,
            require_request_uri_registration: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use oidc_types::jose::jwk_set::JwkSet;

    use crate::configuration::pkce::PKCE;
    use crate::configuration::provider::OpenIDProviderConfiguration;

    #[test]
    fn can_modify_default_configuration() {
        todo!()
    }
}
