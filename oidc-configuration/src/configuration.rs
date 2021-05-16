use std::env;
use std::fs;

use serde::Deserialize;

use crate::error::ConfigError;

type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Deserialize, Debug)]
struct SystemConfig {
    domain: String,
}

#[derive(Deserialize, Debug)]
struct AuthorizationServerConfig {
    scopes_supported: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Config {
    system: SystemConfig,
    authorization_server: AuthorizationServerConfig,
}

pub fn load_config() -> Result<Config> {
    let config_path = env::var("CONFIG_FILE")?;
    let raw_config = fs::read_to_string(config_path)?;
    let config = toml::from_str::<Config>(&raw_config)?;
    Ok(config)
}