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
use tracing::{error, warn};
use x509_parser::error::PEMError;
use x509_parser::pem::Pem;

use oidc_core::client_auth::ClientCredential;
use oidc_core::client_auth::ClientCredential::{
    ClientSecretBasic, ClientSecretJwt, ClientSecretPost, PrivateKeyJwt, SelfSignedTlsClientAuth,
    TlsClientAuth,
};
use oidc_core::client_credentials::{
    BodyParams, ClientSecretCredential, ClientSecretJWTCredential, CredentialError, JWTCredential,
    PrivateKeyJWTCredential, SelfSignedTLSClientAuthCredential, TLSClientAuthCredential,
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
        let mtls_config = provider.mtls();
        if !mtls_config.enabled() && headers.contains_key(mtls_config.certificate_header()) {
            warn!(
                "MTLS config is disabled, but found header with key: {}.\
                If you wish to use MTLS enable it in the provider configuration.",
                mtls_config.certificate_header()
            )
        }
        let pem = if mtls_config.enabled() {
            get_certificate(headers, provider)?
        } else {
            None
        };
        let mut credentials = HashMap::new();
        let mut params: BodyParams = from_bytes(body_bytes)?;
        let mut client_id = params.client_id;
        if client_id.is_some() {
            let credential = TlsClientAuth(TLSClientAuthCredential::new(pem.clone()));
            credentials.insert(AuthMethod::TlsClientAuth, credential);
            let credential =
                SelfSignedTlsClientAuth(SelfSignedTLSClientAuthCredential::new(pem.clone()));
            credentials.insert(AuthMethod::SelfSignedTlsClientAuth, credential);
        }

        if let Ok(header) = Authorization::<Basic>::from_headers(headers) {
            let id = header.username();
            let secret = header.password();
            let (id, credential) = parse_credential(id, secret, pem.clone())?;

            validate_client_id("Authorization header", client_id.as_ref(), id)?;
            client_id = Some(id);
            credentials.insert(AuthMethod::ClientSecretBasic, ClientSecretBasic(credential));
        }
        if let Ok(credential) = ClientSecretCredential::try_from(&mut params) {
            credentials.insert(
                AuthMethod::ClientSecretPost,
                ClientSecretPost(credential.with_cert(pem.clone())),
            );
        }
        match JWTCredential::try_from(&mut params) {
            Ok(credential) => {
                let id = credential.client_id()?;
                validate_client_id("client_assertion", client_id.as_ref(), id)?;
                client_id = Some(id);
                let parsed_credential =
                    ClientSecretJWTCredential::new(credential.clone(), pem.clone());
                credentials.insert(
                    AuthMethod::ClientSecretJwt,
                    ClientSecretJwt(parsed_credential),
                );
                let parsed_credential = PrivateKeyJWTCredential::new(credential, pem);
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
            client_id: client_id.ok_or(CredentialsError::MissingClientId)?,
        })
    }

    pub fn take(&mut self, key: &AuthMethod) -> Option<ClientCredential> {
        self.credentials.remove(key)
    }
}

fn parse_credential(
    client_id: &str,
    secret: &str,
    pem: Option<Pem>,
) -> Result<(ClientID, ClientSecretCredential), CredentialsError> {
    let client_id = parse_client_id(client_id)?;
    let secret = urlencoding::decode(secret)?;
    Ok((
        client_id,
        ClientSecretCredential::new(secret.to_string(), pem),
    ))
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
    client_id: Option<&ClientID>,
    id: ClientID,
) -> Result<(), CredentialsError> {
    if let Some(b_cid) = client_id {
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
            | CredentialsError::ParsePem(_)
            | CredentialsError::CredentialError(_) => OpenIdError::invalid_request(err.to_string()),
        }
    }
}

fn get_certificate(
    headers: &HeaderMap,
    provider: &OpenIDProviderConfiguration,
) -> Result<Option<Pem>, CredentialsError> {
    let cert_header = provider.mtls().certificate_header();
    let cert = headers
        .get(cert_header)
        .map(|header| Cursor::new(header.as_bytes()))
        .map(Pem::read)
        .transpose()?
        .map(|(pem, _)| pem);
    Ok(cert)
}
