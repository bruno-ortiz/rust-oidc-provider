use serde::Deserialize;
use url::Url;

use crate::client::ClientID;
use crate::grant_type::GrantType;
use crate::scopes::Scopes;

#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    grant_type: GrantType,
    client_id: ClientID,
    redirect_uri: Url,
    code: Option<String>,
    scope: Option<Scopes>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}
