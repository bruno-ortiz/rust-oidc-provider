use crate::simple_id_token::SimpleIdToken;
use serde::{Serialize, Serializer};
use serde_with::skip_serializing_none;
use time::Duration;
use uuid::Uuid;

#[skip_serializing_none]
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct TokenResponse {
    access_token: Uuid,
    token_type: String,
    #[serde(serialize_with = "serialize_duration")]
    expires_in: Duration,
    refresh_token: Option<Uuid>,
    id_token: Option<SimpleIdToken>,
}

impl TokenResponse {
    pub fn new(
        token: Uuid,
        token_type: String,
        expires_in: Duration,
        refresh_token: Option<Uuid>,
        id_token: Option<SimpleIdToken>,
    ) -> Self {
        Self {
            access_token: token,
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
