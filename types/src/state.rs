use crate::hash::Hashable;
use crate::url_encodable::UrlEncodable;
use indexmap::IndexMap;
use serde::Deserialize;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct State(String);

impl State {
    pub fn new<T: Into<String>>(value: T) -> Self {
        Self(value.into())
    }
}

impl Display for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Hashable for State {
    fn identifier(&self) -> &str {
        &self.0
    }
}

impl UrlEncodable for State {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("state".to_owned(), self.0);
        map
    }
}
