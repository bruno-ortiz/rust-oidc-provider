use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Subject(String);

impl Subject {
    pub fn new<ID: Into<String>>(id: ID) -> Self {
        Subject(id.into())
    }
}

impl AsRef<str> for Subject {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
