use crate::id_token::IdToken;
use crate::refresh_token::RefreshToken;
use serde::{Serialize, Serializer};
use serde_with::skip_serializing_none;
use time::Duration;

#[skip_serializing_none]
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct TokenResponse {
    token: String,
    token_type: String,
    #[serde(serialize_with = "serialize_duration")]
    expires_in: Duration,
    refresh_token: Option<RefreshToken>,
    id_token: Option<IdToken>,
}

impl TokenResponse {
    pub fn new(
        token: String,
        token_type: String,
        expires_in: Duration,
        refresh_token: Option<RefreshToken>,
        id_token: Option<IdToken>,
    ) -> Self {
        Self {
            token,
            token_type,
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
