use indexmap::IndexMap;
use oidc_types::hash::Hashable;
use time::Duration;

use crate::response_type::UrlEncodable;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AccessToken {
    token: String,
    token_type: String,
    expires_in: Duration,
    refresh_token: Option<String>,
}

impl AccessToken {
    pub fn new(
        token: String,
        token_type: String,
        expires_in: Duration,
        refresh_token: Option<String>,
    ) -> Self {
        Self {
            token,
            token_type,
            expires_in,
            refresh_token,
        }
    }
}

impl Hashable for AccessToken {
    fn identifier(&self) -> &str {
        &self.token
    }
}

impl UrlEncodable for AccessToken {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("access_token".to_owned(), self.token);
        map.insert("token_type".to_owned(), self.token_type);
        map.insert(
            "expires_in".to_owned(),
            self.expires_in.whole_seconds().to_string(),
        );
        if let Some(rt) = self.refresh_token {
            map.insert("refresh_token".to_owned(), rt);
        }
        map
    }
}
