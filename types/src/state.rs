use crate::hash::Hashable;
use crate::url_encodable::UrlEncodable;
use indexmap::IndexMap;
use serde::Deserialize;


#[derive(Debug, Clone, Deserialize)]
pub struct State(String);

impl State {
    pub fn new<T: Into<String>>(value: T) -> Self {
        Self(value.into())
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
