use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum CodeChallengeMethod {
    Plain,
    S256,
    None,
}
