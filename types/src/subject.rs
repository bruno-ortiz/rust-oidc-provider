use serde::Deserialize;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct Subject(String);

impl Subject {
    pub fn new<ID: Into<String>>(id: ID) -> Self {
        Subject(id.into())
    }
}

impl From<&Subject> for String {
    fn from(sub: &Subject) -> Self {
        sub.0.to_owned()
    }
}

impl AsRef<str> for Subject {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for Subject {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
