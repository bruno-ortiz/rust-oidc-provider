use indexmap::IndexMap;
use serde::Deserialize;
use uuid::Uuid;

use crate::hash::Hashable;
use crate::url_encodable::UrlEncodable;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize)]
pub struct Code(String);

impl Hashable for Code {
    fn identifier(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for Code {
    fn from(c: String) -> Self {
        Self(c)
    }
}

impl UrlEncodable for Code {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("code".to_owned(), self.0);
        map
    }
}

impl Default for Code {
    fn default() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}
