use std::env;
use std::fs;

use serde::{Deserialize};

use crate::error::ConfigError;

#[derive(Deserialize, Debug)]
struct AuthConfig {
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    code_challenge_methods_supported: Option<String>,
    jwks_uri: Option<String>,
    registration_endpoint: Option<String>,
    scopes_supported: Option<Vec<String>>,
    response_types_supported: Option<Vec<String>>,
    response_modes_supported: Option<Vec<String>>,
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

#[derive(Deserialize, Debug)]
struct SystemConfig {
    domain: String,
}

#[derive(Deserialize, Debug)]
pub struct Config {
    system: SystemConfig,
    authorization_server: AuthConfig,
}

pub type Result<T> = std::result::Result<T, ConfigError>;

pub fn load_config() -> Result<Config> {
    let config_path = env::var("CONFIG_FILE")?;
    let raw_config = fs::read_to_string(config_path)?;
    let config = toml::from_str::<Config>(&raw_config)?;
    Ok(config)
}