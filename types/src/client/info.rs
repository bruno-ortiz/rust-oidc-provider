use std::fmt::{Display, Formatter};
use std::ops::Deref;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::auth_method::AuthMethod;
use crate::grant_type::GrantType;
use crate::jose::jwk_set::JwkSet;
use crate::jose::jwt::JWT;
use crate::response_type::ResponseTypeValue;
use crate::scopes::Scopes;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct ClientID(Uuid);

impl ClientID {
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<ClientID> for String {
    fn from(id: ClientID) -> Self {
        id.0.to_string()
    }
}

impl Display for ClientID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", 0)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientMetadata {
    pub redirect_uris: Vec<Url>,
    pub token_endpoint_auth_method: Option<AuthMethod>,
    pub grant_types: Vec<GrantType>,
    pub response_types: Vec<ResponseTypeValue>,
    pub scope: Scopes,
    // TODO: implement RFC5646 for client_name, client_uri, logo_uri, tos_uri, policy_uri
    pub client_name: Option<String>,
    pub client_uri: Option<Url>,
    pub logo_uri: Option<Url>,
    pub tos_uri: Option<Url>,
    pub policy_uri: Option<Url>,
    pub contacts: Vec<String>,
    pub jwks_uri: Option<Url>,
    pub jwks: Option<JwkSet>,
    pub software_id: Option<Uuid>,
    pub software_version: Option<String>,
    pub software_statement: Option<JWT>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientInformation {
    pub id: ClientID,
    pub issue_date: DateTime<Utc>,
    pub metadata: ClientMetadata,
}
