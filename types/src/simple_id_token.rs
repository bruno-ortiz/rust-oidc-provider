use crate::url_encodable::UrlEncodable;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimpleIdToken(String);

impl SimpleIdToken {
    pub fn new(repr: String) -> Self {
        Self(repr)
    }
}

impl UrlEncodable for SimpleIdToken {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("id_token".to_owned(), self.0);
        map
    }
}
