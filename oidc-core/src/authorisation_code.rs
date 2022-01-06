use oidc_types::hash::Hashable;
use std::collections::HashMap;

use crate::response_type::UrlEncodable;

#[derive(Debug)]
pub struct AuthorisationCode(pub(crate) String);

impl Hashable for AuthorisationCode {
    fn identifier(&self) -> &str {
        &self.0
    }
}

impl UrlEncodable for AuthorisationCode {
    fn params(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("code".to_owned(), self.0.clone());
        map
    }
}
