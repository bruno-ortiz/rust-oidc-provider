use serde::Deserialize;

use oidc_types::jose::jwk_set::JwkSet;
use oidc_types::pkce::CodeChallengeMethod;
use oidc_types::response_mode::ResponseMode;
use oidc_types::response_type;
use oidc_types::response_type::{ResponseType, ResponseTypeValue};
use oidc_types::response_type::ResponseTypeValue::{Code, IdToken};

use crate::configuration::pkce::PKCE;
use crate::configuration::routes::Routes;

#[derive(Debug)]
pub struct OpenIDProviderConfiguration {
    pkce: PKCE,
    jwks: JwkSet,
    //TODO: impl routes
    routes: Routes,
    response_types_supported: Vec<ResponseType>,
    scopes_supported: Option<Vec<String>>,
    grant_types_supported: Option<Vec<String>>,
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
    fn new() -> Self {
        OpenIDProviderConfiguration::default()
    }

    pub fn pkce(mut self, pkce: PKCE) -> Self {
        self.pkce = pkce;
        self
    }

    pub fn jwks<T>(mut self, jwks: T) -> Self
        where
            T: Into<JwkSet>,
    {
        self.jwks = jwks.into();
        self
    }

    pub fn response_types(mut self, response_types: Vec<ResponseType>) -> Self {
        self.response_types_supported = response_types;
        self
    }
}

impl Default for OpenIDProviderConfiguration {
    fn default() -> Self {
        OpenIDProviderConfiguration {
            pkce: PKCE::default(),
            jwks: JwkSet::default(),
            routes: Routes,
            response_types_supported: vec![
                response_type![Code, IdToken],
                response_type![Code],
                response_type![IdToken],
                response_type![ResponseTypeValue::None],
            ],
            scopes_supported: None,
            grant_types_supported: None,
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

    use crate::configuration::configuration::OpenIDProviderConfiguration;
    use crate::configuration::pkce::PKCE;

    #[test]
    fn can_modify_default_configuration() {
        let mut config = OpenIDProviderConfiguration::new()
            .jwks(JwkSet::new(vec![]))
            .pkce(PKCE::default());
    }
}
