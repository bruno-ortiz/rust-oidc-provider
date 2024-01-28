use crate::hash::Hashable;
use crate::url_encodable::UrlEncodable;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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
    fn identifier(&self) -> String {
        self.0.clone()
    }
}

impl UrlEncodable for State {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("state".to_owned(), self.0);
        map
    }
}
