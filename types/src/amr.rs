use std::fmt::{Display, Formatter};

use serde::Deserialize;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct Amr(
    #[serde(deserialize_with = "crate::utils::space_delimited_deserializer")] Vec<String>,
);

impl From<String> for Amr {
    fn from(s: String) -> Self {
        Amr(s.split(' ').map(|s| s.to_owned()).collect())
    }
}

impl Display for Amr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.join(" "))
    }
}
