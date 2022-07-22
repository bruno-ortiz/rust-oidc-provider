use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CodeChallengeMethod {
    Plain,
    S256,
    None,
}

impl Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CodeChallengeMethod::Plain => write!(f, "plain"),
            CodeChallengeMethod::S256 => write!(f, "S256"),
            CodeChallengeMethod::None => write!(f, "none"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CodeChallenge(String);

impl CodeChallenge {
    pub fn new<S: Into<String>>(cc: S) -> Self {
        Self(cc.into())
    }
}

impl Display for CodeChallenge {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
