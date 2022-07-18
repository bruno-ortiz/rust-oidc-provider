use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Error parsing prompt parameter {}", .0)]
pub struct ParseError(String);

#[derive(Serialize, Deserialize, Debug, Copy, Clone, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount,
}

impl TryFrom<&str> for Prompt {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let prompt = match value {
            "none" => Prompt::None,
            "login" => Prompt::Login,
            "consent" => Prompt::Consent,
            "select_account" => Prompt::SelectAccount,
            &_ => return Err(ParseError(value.to_owned())),
        };
        Ok(prompt)
    }
}
