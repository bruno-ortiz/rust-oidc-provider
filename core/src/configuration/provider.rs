use std::fmt::Debug;

use josekit::jwk::Jwk;
use url::Url;

use oidc_types::grant_type::GrantType;
use oidc_types::issuer::Issuer;
use oidc_types::jose::jwk_set::JwkSet;
use oidc_types::response_mode::ResponseMode;
use oidc_types::response_type::ResponseType;
use oidc_types::response_type::ResponseTypeValue::{Code, IdToken};
use oidc_types::scopes::Scopes;
use oidc_types::{response_type, scopes};

use crate::configuration::adapter_container::AdapterContainer;
use crate::configuration::pkce::PKCE;
use crate::configuration::routes::Routes;
use crate::services::interaction::Interaction;

pub struct OpenIDProviderConfiguration {
    pkce: PKCE,
    jwks: JwkSet,
    routes: Routes,
    adapters: AdapterContainer,
    response_types_supported: Vec<ResponseType>,
    response_modes_supported: Vec<ResponseMode>,
    jwt_secure_response_mode: bool,
    issuer: Issuer,
    grant_types_supported: Vec<GrantType>,
    scopes_supported: Scopes,
    interaction_config:
        Box<dyn Fn(&Interaction, &OpenIDProviderConfiguration) -> Url + Send + Sync>,
    acr_values_supported: Option<Vec<String>>,
    subject_types_supported: Option<Vec<String>>,
    id_token_signing_alg_values_supported: Option<Vec<String>>,
    id_token_encryption_alg_values_supported: Option<Vec<String>>,
    id_token_encryption_enc_values_supported: Option<Vec<String>>,
    userinfo_signing_alg_values_supported: Option<Vec<String>>,
    userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    request_object_signing_alg_values_supported: Option<Vec<String>>,
    request_object_encryption_alg_values_supported: Option<Vec<String>>,
    request_object_encryption_enc_values_supported: Option<Vec<String>>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
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

impl OpenIDProviderConfiguration {
    pub fn new<T, E: Debug>(issuer: T) -> Self
    where
        T: TryInto<Url, Error = E>,
    {
        OpenIDProviderConfiguration {
            issuer: Issuer::new(issuer),
            ..OpenIDProviderConfiguration::default()
        }
    }

    pub fn with_pkce(mut self, pkce: PKCE) -> Self {
        self.pkce = pkce;
        self
    }

    pub fn with_jwks<T>(mut self, jwks: T) -> Self
    where
        T: Into<JwkSet>,
    {
        self.jwks = jwks.into();
        self
    }

    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    pub fn with_response_types(mut self, response_types: Vec<ResponseType>) -> Self {
        self.response_types_supported = response_types;
        self
    }

    pub fn response_types(&self) -> &Vec<ResponseType> {
        &self.response_types_supported
    }

    pub fn with_routes(mut self, routes: Routes) -> Self {
        self.routes = routes;
        self
    }

    pub fn routes(&self) -> &Routes {
        &self.routes
    }

    pub fn with_adapters(mut self, adapters: AdapterContainer) -> Self {
        self.adapters = adapters;
        self
    }

    pub fn adapters(&self) -> &AdapterContainer {
        &self.adapters
    }

    pub fn response_modes(&self) -> &Vec<ResponseMode> {
        &self.response_modes_supported
    }

    pub fn interaction(
        &self,
    ) -> &(dyn Fn(&Interaction, &OpenIDProviderConfiguration) -> Url + Send + Sync) {
        &self.interaction_config
    }

    pub fn enable_jarm(mut self) -> Self {
        self.jwt_secure_response_mode = true;
        self.response_modes_supported.extend([
            ResponseMode::Jwt,
            ResponseMode::QueryJwt,
            ResponseMode::FragmentJwt,
        ]);
        self
    }

    pub fn is_jarm_enabled(&self) -> bool {
        self.jwt_secure_response_mode
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
            issuer: Issuer::new("http://localhost:3000"),
            scopes_supported: scopes!("openid"),
            grant_types_supported: vec![
                GrantType::AuthorizationCode,
                GrantType::ClientCredentials,
                GrantType::RefreshToken,
            ],
            interaction_config: Box::new(|interaction, config| {
                let base_url = config.issuer.inner_ref();
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
            acr_values_supported: None,
            subject_types_supported: None,
            id_token_signing_alg_values_supported: None,
            id_token_encryption_alg_values_supported: None,
            id_token_encryption_enc_values_supported: None,
            userinfo_signing_alg_values_supported: None,
            userinfo_encryption_alg_values_supported: None,
            userinfo_encryption_enc_values_supported: None,
            request_object_signing_alg_values_supported: None,
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            token_endpoint_auth_methods_supported: None,
            token_endpoint_auth_signing_alg_values_supported: None,
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
        let _config = OpenIDProviderConfiguration::new("http://localhost:3000")
            .with_jwks(JwkSet::new(vec![]))
            .with_pkce(PKCE::default());
    }
}
