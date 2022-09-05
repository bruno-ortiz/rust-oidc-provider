use crate::hash::Hashable;
use crate::jose::jwt::JWT;
use crate::refresh_token::RefreshToken;
use indexmap::IndexMap;
use serde::{Serialize, Serializer};
use serde_with::skip_serializing_none;
use time::Duration;
use uuid::Uuid;

use crate::url_encodable::UrlEncodable;

#[skip_serializing_none]
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AccessToken {
    token: String,
    token_type: String,
    #[serde(serialize_with = "serialize_duration")]
    expires_in: Duration,
    refresh_token: Option<RefreshToken>,
    id_token: Option<JWT>,
}

impl AccessToken {
    pub const BEARER_TYPE: &'static str = "Bearer";

    pub fn new<TT: Into<String>>(
        token_type: TT,
        expires_in: Duration,
        refresh_token: Option<RefreshToken>,
        id_token: Option<JWT>,
    ) -> Self {
        Self {
            token: Uuid::new_v4().to_string(),
            token_type: token_type.into(),
            expires_in,
            refresh_token,
            id_token,
        }
    }
}

pub fn serialize_duration<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_i64(duration.whole_seconds())
}
