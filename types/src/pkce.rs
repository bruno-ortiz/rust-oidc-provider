use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum CodeChallengeMethod {
    Plain,
    S256,
    None,
}

#[derive(Debug, Clone)]
pub struct CodeChallenge(String);
