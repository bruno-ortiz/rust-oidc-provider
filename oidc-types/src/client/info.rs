use chrono::{DateTime, Utc};
use josekit::jwk::JwkSet;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::auth_method::AuthMethod;
use crate::grant_type::GrantType;
use crate::jose::jws::JWS;
use crate::response_type::ResponseTypeValue;
use crate::scopes::Scopes;

#[derive(Serialize, Deserialize)]
pub struct ClientID(String);

#[derive(Serialize, Deserialize)]
pub struct ClientMetadata {
    redirect_uris: Vec<Url>,
    token_endpoint_auth_method: Option<AuthMethod>,
    grant_types: Vec<GrantType>,
    response_types: Vec<ResponseTypeValue>,
    scope: Option<Scopes>,
    // TODO: implement RFC5646 for client_name, client_uri, logo_uri, tos_uri, policy_uri
    client_name: Option<String>,
    client_uri: Option<Url>,
    logo_uri: Option<Url>,
    tos_uri: Option<Url>,
    policy_uri: Option<Url>,
    contacts: Vec<String>,
    jwks_uri: Option<Url>,
    // jwks: Option<JwkSet>,
    software_id: Option<Uuid>,
    software_version: Option<String>,
    software_statement: Option<JWS>,
}

#[derive(Serialize, Deserialize)]
pub struct ClientInformation {
    id: ClientID,
    issue_date: DateTime<Utc>,
    metadata: ClientMetadata,
}
