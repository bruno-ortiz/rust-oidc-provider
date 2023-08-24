use std::fmt;
use std::fmt::{Display, Formatter};

use serde::Deserialize;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct Acr(
    #[serde(deserialize_with = "crate::utils::space_delimited_deserializer")] Vec<String>,
);

impl Acr {
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|it| it.as_str())
    }
}

impl From<String> for Acr {
    fn from(s: String) -> Self {
        Acr(s.split(' ').map(|s| s.to_owned()).collect())
    }
}

impl Display for Acr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.join(" "))
    }
}

impl Default for Acr {
    fn default() -> Self {
        Self(vec!["0".to_owned()])
    }
}
