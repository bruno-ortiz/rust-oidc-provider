use std::collections::HashMap;

use crate::hash::Hashable;
use crate::response_type::UrlEncodable;

#[derive(Debug)]
pub struct AccessToken(String);

impl Hashable for AccessToken {
    fn identifier(&self) -> &str {
        &self.0
    }
}

impl UrlEncodable for AccessToken {
    fn params(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("access_token".to_owned(), self.0.clone());
        map
    }
}
