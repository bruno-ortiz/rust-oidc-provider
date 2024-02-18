use std::collections::HashMap;
use std::io::Cursor;
use std::str::FromStr;
use std::string::FromUtf8Error;

use axum::body::Bytes;
use axum::http::StatusCode;
use axum_extra::headers::authorization::Basic;
use axum_extra::headers::{Authorization, HeaderMapExt};
use hyper::HeaderMap;
use serde::de::value::Error as SerdeError;
use serde_urlencoded::from_bytes;
use thiserror::Error;
use tracing::error;
use x509_parser::error::PEMError;
use x509_parser::pem::Pem;

use oidc_core::client_credentials::ClientCredential::{
    ClientSecretBasic, ClientSecretJwt, ClientSecretPost, PrivateKeyJwt, SelfSignedTlsClientAuth,
    TlsClientAuth,
};
use oidc_core::client_credentials::{
    BodyParams, ClientCredential, ClientSecretCredential, ClientSecretJWTCredential,
    CredentialError, JWTCredential, PrivateKeyJWTCredential, SelfSignedTLSClientAuthCredential,
    TLSClientAuthCredential,
};
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::error::OpenIdError;
use oidc_types::auth_method::AuthMethod;
use oidc_types::client::ClientID;

#[derive(Debug, Error)]
pub enum CredentialsError {
    #[error("Invalid client_id {}", .0)]
    InvalidClientId(String),
    #[error("Missing client_id")]
    MissingClientId,
    #[error("Missing secret in the Authorization header")]
    MissingSecret,
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error("{}", .0)]
    MismatchedClientId(String),
    #[error("{}", .0)]
    UTF8Err(#[from] FromUtf8Error),
    #[error("Error parsing body params, {:?}", .0)]
    ParseBody(#[from] SerdeError),
    #[error("Missing certificate in request. Looked at header: {}", .0)]
    MissingCertificate(&'static str),
    #[error("Error parsing pem certificate: {}", .0)]
    ParsePem(#[from] PEMError),
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub client_id: ClientID,
    credentials: HashMap<AuthMethod, ClientCredential>,
}

impl Credentials {
    pub async fn parse_credentials(
        headers: &HeaderMap,
        body_bytes: &Bytes,
        provider: &OpenIDProviderConfiguration,
    ) -> Result<Credentials, CredentialsError> {
        let mut credentials = HashMap::new();
        let mut params: BodyParams = from_bytes(body_bytes)?;
        let mut client_id = params.client_id.ok_or(CredentialsError::MissingClientId);
        if let Ok(id) = client_id {
            client_id = Ok(id);
            let cert_header = provider.mtls().certificate_header();
            let cert = headers
                .get(cert_header)
                .map(|header| Cursor::new(header.as_bytes()))
                .ok_or(CredentialsError::MissingCertificate(cert_header))?;
            let (pem, _) = Pem::read(cert)?;

            let credential = TlsClientAuth(TLSClientAuthCredential::new(pem.clone()));
            credentials.insert(AuthMethod::TlsClientAuth, credential);
            let credential = SelfSignedTlsClientAuth(SelfSignedTLSClientAuthCredential::new(pem));
            credentials.insert(AuthMethod::SelfSignedTlsClientAuth, credential);
        }

        if let Ok(header) = Authorization::<Basic>::from_headers(headers) {
            let id = header.username();
            let secret = header.password();
            let (id, credential) = parse_credential(id, secret)?;

            validate_client_id("Authorization header", &client_id, id)?;
            client_id = Ok(id);
            credentials.insert(AuthMethod::ClientSecretBasic, ClientSecretBasic(credential));
        }
        if let Ok(credential) = ClientSecretCredential::try_from(&mut params) {
            credentials.insert(AuthMethod::ClientSecretPost, ClientSecretPost(credential));
        }
        match JWTCredential::try_from(&mut params) {
            Ok(credential) => {
                let id = credential.client_id()?;
                validate_client_id("client_assertion", &client_id, id)?;
                client_id = Ok(id);
                let parsed_credential = ClientSecretJWTCredential::from(credential.clone());
                credentials.insert(
                    AuthMethod::ClientSecretJwt,
                    ClientSecretJwt(parsed_credential),
                );
                let parsed_credential = PrivateKeyJWTCredential::from(credential);
                credentials.insert(AuthMethod::PrivateKeyJwt, PrivateKeyJwt(parsed_credential));
            }
            Err(err) => match err {
                CredentialError::InvalidClientAssertion(_)
                | CredentialError::InvalidClientAssertionType(_) => return Err(err.into()),
                _ => { /* Ok */ }
            },
        }

        if credentials.is_empty() {
            credentials.insert(AuthMethod::None, ClientCredential::None);
        }
        Ok(Credentials {
            credentials,
            client_id: client_id?,
        })
    }

    pub fn take(&mut self, key: &AuthMethod) -> Option<ClientCredential> {
        self.credentials.remove(key)
    }
}

fn parse_credential(
    client_id: &str,
    secret: &str,
) -> Result<(ClientID, ClientSecretCredential), CredentialsError> {
    let client_id = parse_client_id(client_id)?;
    let secret = urlencoding::decode(secret)?;
    Ok((client_id, ClientSecretCredential::new(secret)))
}

fn parse_client_id(client_id: &str) -> Result<ClientID, CredentialsError> {
    let client_id = ClientID::from_str(client_id).map_err(|err| {
        error!("Invalid client_id {}", err);
        CredentialsError::InvalidClientId(client_id.to_owned())
    })?;
    Ok(client_id)
}

fn validate_client_id(
    location: &str,
    client_id: &Result<ClientID, CredentialsError>,
    id: ClientID,
) -> Result<(), CredentialsError> {
    if let Ok(b_cid) = client_id {
        if *b_cid != id {
            return Err(CredentialsError::MismatchedClientId(format!(
                "client_id in {} must be equal to client_id in body",
                location
            )));
        }
    }
    Ok(())
}

trait AuthorizationBasicExt {
    fn from_headers(
        headers: &HeaderMap,
    ) -> Result<Authorization<Basic>, (StatusCode, &'static str)>;
}

impl AuthorizationBasicExt for Authorization<Basic> {
    fn from_headers(
        headers: &HeaderMap,
    ) -> Result<Authorization<Basic>, (StatusCode, &'static str)> {
        match headers.typed_try_get::<Authorization<Basic>>() {
            Ok(Some(header)) => Ok(header),
            Ok(None) => Err((StatusCode::BAD_REQUEST, "`Authorization` header is missing")),
            Err(_) => Err((
                StatusCode::BAD_REQUEST,
                "Error decoding`Authorization` header",
            )),
        }
    }
}

impl From<CredentialsError> for OpenIdError {
    fn from(err: CredentialsError) -> Self {
        match err {
            CredentialsError::InvalidClientId(_)
            | CredentialsError::MissingClientId
            | CredentialsError::MissingSecret
            | CredentialsError::MismatchedClientId(_)
            | CredentialsError::ParseBody(_)
            | CredentialsError::UTF8Err(_)
            | CredentialsError::MissingCertificate(_)
            | CredentialsError::ParsePem(_)
            | CredentialsError::CredentialError(_) => OpenIdError::invalid_request(err.to_string()),
        }
    }
}
