use crate::url_encodable::UrlEncodable;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimpleIdToken(String);

impl SimpleIdToken {
    pub fn new(repr: String) -> Self {
        Self(repr)
    }
}

impl AsRef<str> for SimpleIdToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for SimpleIdToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl UrlEncodable for SimpleIdToken {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("id_token".to_owned(), self.0);
        map
    }
}
