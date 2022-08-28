use crate::hash::Hashable;
use crate::identifiable::Identifiable;
use crate::refresh_token::RefreshToken;
use crate::scopes::Scopes;
use indexmap::IndexMap;
use serde::{Serialize, Serializer};
use serde_with::skip_serializing_none;
use time::Duration;
use uuid::Uuid;

use crate::url_encodable::UrlEncodable;

pub const BEARER_TYPE: &str = "Bearer";

#[skip_serializing_none]
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AccessToken {
    token: String,
    token_type: String,
    #[serde(serialize_with = "serialize_duration")]
    expires_in: Duration,
    refresh_token: Option<RefreshToken>,
    #[serde(skip)]
    scopes: Option<Scopes>,
}

impl AccessToken {
    pub fn new<TT: Into<String>>(
        token_type: TT,
        expires_in: Duration,
        refresh_token: Option<RefreshToken>,
        scopes: Option<Scopes>,
    ) -> Self {
        Self {
            token: Uuid::new_v4().to_string(),
            token_type: token_type.into(),
            expires_in,
            refresh_token,
            scopes,
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
            map.insert("refresh_token".to_owned(), rt.to_string());
        }
        map
    }
}

impl Identifiable<String> for AccessToken {
    fn id(&self) -> String {
        self.token.clone()
    }
}

pub fn serialize_duration<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_i64(duration.whole_seconds())
}
