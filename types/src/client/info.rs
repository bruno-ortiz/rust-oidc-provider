use std::fmt::{Display, Formatter};
use std::str::FromStr;

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::auth_method::AuthMethod;
use crate::grant_type::GrantType;
use crate::hashed_secret::HashedSecret;
use crate::identifiable::Identifiable;
use crate::jose::jwk_set::JwkSet;
use crate::jose::jwt::JWT;
use crate::response_type::ResponseTypeValue;
use crate::scopes::Scopes;

#[derive(Debug, Clone, Error)]
#[error("Cannot parse ClientID. Reason: {}", .0)]
pub struct ParseError(uuid::Error);

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct ClientID(Uuid);

impl ClientID {
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }
}

impl FromStr for ClientID {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(s).map_err(ParseError)?;
        Ok(ClientID::new(uuid))
    }
}

impl From<ClientID> for String {
    fn from(id: ClientID) -> Self {
        id.0.to_string()
    }
}

impl Display for ClientID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for ClientID {
    fn default() -> Self {
        Self(Uuid::new_v4())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, Default)]
#[builder(setter(into, strip_option), default)]
pub struct ClientMetadata {
    pub redirect_uris: Vec<Url>,
    pub token_endpoint_auth_method: AuthMethod,
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

#[derive(Debug, Clone)]
pub struct ClientInformation {
    pub id: ClientID,
    pub issue_date: OffsetDateTime,
    pub secret: HashedSecret,
    pub secret_expires_at: Option<OffsetDateTime>,
    pub metadata: ClientMetadata,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedClient(ClientInformation);

impl AuthenticatedClient {
    pub fn new(client: ClientInformation) -> Self {
        Self(client)
    }

    pub fn id(&self) -> ClientID {
        self.0.id
    }

    pub fn allows_grant(&self, grant_type: GrantType) -> bool {
        self.0.metadata.grant_types.contains(&grant_type)
    }
    pub fn auth_method(&self) -> AuthMethod {
        self.0.metadata.token_endpoint_auth_method
    }
}

impl AsRef<ClientInformation> for AuthenticatedClient {
    fn as_ref(&self) -> &ClientInformation {
        &self.0
    }
}

impl Identifiable<ClientID> for ClientInformation {
    fn id(&self) -> ClientID {
        self.id
    }
}
