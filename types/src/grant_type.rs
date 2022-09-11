use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
    Implicit,
    ClientCredentials,
}

impl Display for GrantType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantType::AuthorizationCode => write!(f, "authorization_code"),
            GrantType::RefreshToken => write!(f, "refresh_token"),
            GrantType::Implicit => write!(f, "implicit"),
            GrantType::ClientCredentials => write!(f, "client_credentials"),
        }
    }
}
