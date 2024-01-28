use indexmap::IndexMap;
use serde::Deserialize;
use std::fmt::{Display, Formatter};
use uuid::Uuid;

use crate::hash::Hashable;
use crate::url_encodable::UrlEncodable;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize)]
pub struct Code(String);

impl Code {
    pub fn random() -> Self {
        Code::default()
    }
}

impl Hashable for Code {
    fn identifier(&self) -> String {
        self.0.clone()
    }
}

impl<T: Into<String>> From<T> for Code {
    fn from(c: T) -> Self {
        Self(c.into())
    }
}

impl AsRef<str> for Code {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}
impl UrlEncodable for Code {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("code".to_owned(), self.0);
        map
    }
}

impl Display for Code {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for Code {
    fn default() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}
