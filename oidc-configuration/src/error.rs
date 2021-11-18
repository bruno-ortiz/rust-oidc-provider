use std::env::VarError;
use std::fmt::Formatter;
use std::io::Error;
use std::{error, fmt};
use toml::de;

#[derive(Debug)]
pub enum ConfigError {
    Env(VarError),
    IO(Error),
    Parse(de::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Error reading config.")?;
        match self {
            ConfigError::Env(e) => {
                writeln!(f, "Caused by environment error: {}", e)
            }
            ConfigError::IO(e) => {
                writeln!(f, "Caused by io error: {}", e)
            }
            ConfigError::Parse(e) => {
                writeln!(f, "Caused by parse error: {}", e)
            }
        }
    }
}

impl error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ConfigError::Env(e) => Some(e),
            ConfigError::IO(e) => Some(e),
            ConfigError::Parse(e) => Some(e),
        }
    }
}

impl From<Error> for ConfigError {
    fn from(err: Error) -> Self {
        ConfigError::IO(err)
    }
}

impl From<VarError> for ConfigError {
    fn from(err: VarError) -> Self {
        ConfigError::Env(err)
    }
}

impl From<de::Error> for ConfigError {
    fn from(err: de::Error) -> Self {
        ConfigError::Parse(err)
    }
}
