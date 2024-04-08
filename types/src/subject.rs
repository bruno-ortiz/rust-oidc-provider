use std::fmt::{Display, Formatter};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Hash)]
pub struct Subject(String);

impl Subject {
    pub fn new<ID: Into<String>>(id: ID) -> Self {
        Subject(id.into())
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl From<&Subject> for String {
    fn from(sub: &Subject) -> Self {
        sub.0.to_owned()
    }
}

impl From<String> for Subject {
    fn from(sub: String) -> Self {
        Self(sub)
    }
}

impl AsRef<str> for Subject {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for Subject {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl AsRef<[u8]> for Subject {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Display for Subject {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
