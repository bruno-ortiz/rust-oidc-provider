use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    Implicit,
    RefreshToken,
    ClientCredentials,
}