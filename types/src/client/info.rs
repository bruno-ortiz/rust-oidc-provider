use std::fmt::{Display, Formatter};
use std::str::FromStr;

use derive_builder::Builder;
use josekit::jws::RS256;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::application_type::ApplicationType;
use crate::auth_method::AuthMethod;
use crate::grant_type::GrantType;
use crate::jose::jwe::alg::EncryptionAlgorithm;
use crate::jose::jwe::enc::ContentEncryptionAlgorithm;
use crate::jose::jwk_set::JwkSet;
use crate::jose::jws::SigningAlgorithm;
use crate::jose::jwt2::SignedJWT;
use crate::response_type::ResponseTypeValue;
use crate::scopes::Scopes;
use crate::subject_type::SubjectType;

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

#[derive(Serialize, Debug, Clone, Builder)]
#[builder(setter(into, strip_option), default)]
pub struct ClientMetadata {
    pub redirect_uris: Vec<Url>,
    pub response_types: Vec<ResponseTypeValue>,
    pub grant_types: Vec<GrantType>,
    pub application_type: ApplicationType,
    pub contacts: Vec<String>,
    pub client_name: Option<String>,
    pub logo_uri: Option<Url>,
    pub client_uri: Option<Url>,
    pub policy_uri: Option<Url>,
    pub tos_uri: Option<Url>,
    // TODO: implement RFC5646 for client_name, client_uri, logo_uri, tos_uri, policy_uri
    pub jwks_uri: Option<Url>,
    pub jwks: Option<JwkSet>,
    pub sector_identifier_uri: Option<Url>,
    pub subject_type: SubjectType,
    pub id_token_signed_response_alg: SigningAlgorithm,
    pub id_token_encrypted_response_alg: Option<EncryptionAlgorithm>,
    pub id_token_encrypted_response_enc: Option<ContentEncryptionAlgorithm>,
    pub userinfo_signed_response_alg: Option<SigningAlgorithm>,
    pub userinfo_encrypted_response_alg: Option<EncryptionAlgorithm>,
    pub userinfo_encrypted_response_enc: Option<ContentEncryptionAlgorithm>,
    pub request_object_signing_alg: Option<SigningAlgorithm>,
    pub request_object_encryption_alg: Option<EncryptionAlgorithm>,
    pub request_object_encryption_enc: Option<ContentEncryptionAlgorithm>,
    pub authorization_signed_response_alg: SigningAlgorithm,
    pub authorization_encrypted_response_alg: Option<EncryptionAlgorithm>,
    pub authorization_encrypted_response_enc: Option<ContentEncryptionAlgorithm>,
    pub token_endpoint_auth_method: AuthMethod,
    pub token_endpoint_auth_signing_alg: Option<SigningAlgorithm>,
    pub default_max_age: Option<u64>,
    pub require_auth_time: bool,
    pub default_acr_values: Option<Vec<String>>,
    pub initiate_login_uri: Option<Url>,
    pub request_uris: Option<Vec<Url>>,
    pub scope: Scopes,
    pub software_id: Option<Uuid>,
    pub software_version: Option<String>,
    pub software_statement: Option<SignedJWT>,
}

impl Default for ClientMetadata {
    fn default() -> Self {
        ClientMetadata {
            redirect_uris: vec![],
            response_types: vec![ResponseTypeValue::Code],
            grant_types: vec![GrantType::AuthorizationCode],
            application_type: ApplicationType::Web,
            contacts: vec![],
            client_name: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            jwks_uri: None,
            jwks: None,
            sector_identifier_uri: None,
            subject_type: SubjectType::Public,
            // For all "enc" values below:
            //   Default when {endpoint}_encrypted_response_alg is specified should be A128CBC-HS256
            id_token_signed_response_alg: RS256.into(),
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            authorization_signed_response_alg: RS256.into(),
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            token_endpoint_auth_method: Default::default(),
            token_endpoint_auth_signing_alg: None,
            default_max_age: None,
            require_auth_time: false,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            scope: Default::default(),
            software_id: None,
            software_version: None,
            software_statement: None,
        }
    }
}
