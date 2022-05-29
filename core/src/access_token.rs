use indexmap::IndexMap;
use oidc_types::hash::Hashable;
use std::collections::HashMap;

use crate::response_type::UrlEncodable;

#[derive(Debug)]
pub struct AccessToken(String);

impl Hashable for AccessToken {
    fn identifier(&self) -> &str {
        &self.0
    }
}

impl UrlEncodable for AccessToken {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("access_token".to_owned(), self.0);
        map
    }
}
