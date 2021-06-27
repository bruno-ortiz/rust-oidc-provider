use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum CodeChallengeMethod {
    Plain,
    S256,
    None,
}