use indexmap::IndexMap;
use serde::Serialize;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use oidc_types::hash::Hashable;
use oidc_types::identifiable::Identifiable;
use oidc_types::scopes::Scopes;
use oidc_types::url_encodable::UrlEncodable;

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AccessToken {
    pub token: String,
    pub t_type: String,
    pub expires_in: Duration,
    created: OffsetDateTime,
    scopes: Option<Scopes>,
}

impl AccessToken {
    pub const BEARER_TYPE: &'static str = "Bearer";

    pub fn new<TT: Into<String>>(
        token_type: TT,
        expires_in: Duration,
        scopes: Option<Scopes>,
    ) -> Self {
        Self {
            token: Uuid::new_v4().to_string(),
            t_type: token_type.into(),
            created: OffsetDateTime::now_utc(),
            expires_in,
            scopes,
        }
    }

    pub fn bearer(expires_in: Duration, scopes: Option<Scopes>) -> Self {
        Self::new(AccessToken::BEARER_TYPE, expires_in, scopes)
    }

    pub async fn save(
        self,
        config: &OpenIDProviderConfiguration,
    ) -> Result<AccessToken, PersistenceError> {
        config.adapters().token().save(self).await
    }
}

impl Identifiable<String> for AccessToken {
    fn id(&self) -> String {
        self.token.clone()
    }
}

impl UrlEncodable for AccessToken {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("access_token".to_owned(), self.token);
        map.insert("token_type".to_owned(), self.t_type);
        map.insert(
            "expires_in".to_owned(),
            self.expires_in.whole_seconds().to_string(),
        );
        map
    }
}

impl Hashable for AccessToken {
    fn identifier(&self) -> &str {
        &self.token
    }
}
