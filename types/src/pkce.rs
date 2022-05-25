use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CodeChallengeMethod {
    Plain,
    S256,
    None,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CodeChallenge(String);

impl CodeChallenge {
    pub fn new<S: Into<String>>(cc: S) -> Self {
        Self(cc.into())
    }
}
