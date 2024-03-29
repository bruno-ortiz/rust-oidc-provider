use derive_new::new;
use serde::Deserialize;
use thiserror::Error;
use x509_parser::pem::Pem;

use oidc_types::client::{ClientID, ParseError};
use oidc_types::jose::error::JWTError;
use oidc_types::jose::jwt2::{SignedJWT, JWT};

use crate::client_credentials::CredentialError::MissingParam;

const SECRET_KEY: &str = "client_secret";
const ASSERTION_KEY: &str = "client_assertion";
const ASSERTION_TYPE_KEY: &str = "client_assertion_type";
const EXPECTED_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

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
    #[error("Invalid client assertion type: {}", .0)]
    InvalidClientAssertionType(String),
}

#[derive(Debug, Clone, new)]
pub struct ClientSecretCredential(String, Option<Pem>);

impl ClientSecretCredential {
    pub fn consume(self) -> (String, Option<Pem>) {
        (self.0, self.1)
    }

    pub fn with_cert(mut self, cert: Option<Pem>) -> Self {
        self.1 = cert;
        self
    }
}

impl TryFrom<&mut BodyParams> for ClientSecretCredential {
    type Error = CredentialError;

    fn try_from(value: &mut BodyParams) -> Result<Self, Self::Error> {
        let client_secret = value.client_secret.take().ok_or(MissingParam(SECRET_KEY))?;
        Ok(ClientSecretCredential::new(client_secret, None))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct JWTCredential {
    client_assertion_type: String,
    client_assertion: SignedJWT,
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

    pub fn assertion(self) -> SignedJWT {
        self.client_assertion
    }
}

impl TryFrom<&mut BodyParams> for JWTCredential {
    type Error = CredentialError;

    fn try_from(value: &mut BodyParams) -> Result<Self, Self::Error> {
        let client_assertion = value
            .client_assertion
            .take()
            .ok_or(MissingParam(ASSERTION_KEY))?;
        let client_assertion_type = value
            .client_assertion_type
            .take()
            .ok_or(MissingParam(ASSERTION_TYPE_KEY))?;

        if client_assertion_type != EXPECTED_ASSERTION_TYPE {
            return Err(CredentialError::InvalidClientAssertionType(
                client_assertion_type,
            ));
        }
        let client_assertion = SignedJWT::decode_no_verify(client_assertion)?;
        Ok(Self {
            client_assertion,
            client_assertion_type,
        })
    }
}

#[derive(Debug, Clone, new)]
pub struct ClientSecretJWTCredential(JWTCredential, Option<Pem>);

impl ClientSecretJWTCredential {
    pub(crate) fn credential(self) -> (JWTCredential, Option<Pem>) {
        (self.0, self.1)
    }
}

#[derive(Debug, Clone, new)]
pub struct PrivateKeyJWTCredential(JWTCredential, Option<Pem>);

impl PrivateKeyJWTCredential {
    pub(crate) fn credential(self) -> (JWTCredential, Option<Pem>) {
        (self.0, self.1)
    }
}

#[derive(Debug, Clone, new)]
pub struct TLSClientAuthCredential(Option<Pem>);

impl TLSClientAuthCredential {
    pub fn certificate(self) -> Option<Pem> {
        self.0
    }
}

#[derive(Debug, Clone, new)]
pub struct SelfSignedTLSClientAuthCredential(Option<Pem>);

impl SelfSignedTLSClientAuthCredential {
    pub fn certificate(self) -> Option<Pem> {
        self.0
    }
}

#[derive(Debug, Deserialize)]
pub struct BodyParams {
    pub client_id: Option<ClientID>,
    pub client_secret: Option<String>,
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
}
