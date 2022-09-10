use std::collections::HashMap;

use serde::Deserialize;
use thiserror::Error;

use crate::client::{ClientID, ParseError};
use crate::client_credentials::CredentialError::MissingParam;
use crate::jose::error::JWTError;
use crate::jose::jwt::JWT;

const SECRET_KEY: &str = "client_secret";
const ASSERTION_KEY: &str = "client_assertion";
const ASSERTION_TYPE_KEY: &str = "client_assertion_type";

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("Missing sub in client_assertion")]
    MissingSub,
    #[error("Invalid client_id")]
    InvalidClientId(#[from] ParseError),
    #[error("Missing param {}", .0)]
    MissingParam(&'static str),
    #[error("Error parsing body into credential")]
    InvalidClientAssertion(#[from] JWTError),
}

#[derive(Debug, Clone)]
pub enum ClientCredential {
    ClientSecretBasic(ClientSecretCredential),
    ClientSecretPost(ClientSecretCredential),
    ClientSecretJwt(ClientSecretJWTCredential),
    PrivateKeyJwt(PrivateKeyJWTCredential),
    TlsClientAuth(TLSClientAuthCredential),
    SelfSignedTlsClientAuth(SelfSignedTLSClientAuthCredential),
    None,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientSecretCredential(String);

impl ClientSecretCredential {
    pub fn new(secret: String) -> Self {
        Self(secret)
    }

    pub fn secret(self) -> String {
        self.0
    }
}

impl TryFrom<&HashMap<String, String>> for ClientSecretCredential {
    type Error = CredentialError;

    fn try_from(value: &HashMap<String, String>) -> Result<Self, Self::Error> {
        let client_secret = value
            .get(SECRET_KEY)
            .ok_or(MissingParam(SECRET_KEY))
            .cloned()?;
        Ok(ClientSecretCredential::new(client_secret))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct JWTCredential {
    client_assertion_type: String,
    client_assertion: JWT,
}

impl JWTCredential {
    pub fn client_id(&self) -> Result<ClientID, CredentialError> {
        let client_id = self
            .client_assertion
            .payload()
            .subject()
            .ok_or(CredentialError::MissingSub)?
            .parse()?;
        Ok(client_id)
    }

    pub fn assertion_type(&self) -> &str {
        self.client_assertion_type.as_str()
    }
}

impl TryFrom<&HashMap<String, String>> for JWTCredential {
    type Error = CredentialError;

    fn try_from(value: &HashMap<String, String>) -> Result<Self, Self::Error> {
        let client_assertion = value
            .get(ASSERTION_KEY)
            .ok_or(MissingParam(ASSERTION_KEY))?
            .parse()?;
        let client_assertion_type = value
            .get(ASSERTION_TYPE_KEY)
            .ok_or(MissingParam(ASSERTION_TYPE_KEY))
            .cloned()?;
        Ok(Self {
            client_assertion,
            client_assertion_type,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientSecretJWTCredential(JWTCredential);

impl From<JWTCredential> for ClientSecretJWTCredential {
    fn from(value: JWTCredential) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone)]
pub struct PrivateKeyJWTCredential(JWTCredential);

impl From<JWTCredential> for PrivateKeyJWTCredential {
    fn from(value: JWTCredential) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone)]
pub struct TLSClientAuthCredential(ClientID);

impl TLSClientAuthCredential {
    pub fn new(client_id: ClientID) -> Self {
        Self(client_id)
    }
}

#[derive(Debug, Clone)]
pub struct SelfSignedTLSClientAuthCredential(ClientID);

impl SelfSignedTLSClientAuthCredential {
    pub fn new(client_id: ClientID) -> Self {
        Self(client_id)
    }
}
