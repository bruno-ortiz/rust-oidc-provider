use oidc_types::scopes::Scopes;
use serde::Serialize;
use time::OffsetDateTime;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AccessToken {
    token: String,
    token_type: String,
    expires_in: OffsetDateTime,
    scopes: Option<Scopes>,
}
