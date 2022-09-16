use std::collections::HashMap;
use std::str::FromStr;

use axum::body::Bytes;
use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use hyper::HeaderMap;
use serde::de::value::Error as SerdeError;
use serde_urlencoded::from_bytes;
use thiserror::Error;
use tracing::error;

use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::error::OpenIdError;
use oidc_types::auth_method::AuthMethod;
use oidc_types::client::ClientID;
use oidc_types::client_credentials::ClientCredential::{
    ClientSecretBasic, ClientSecretJwt, ClientSecretPost, PrivateKeyJwt, SelfSignedTlsClientAuth,
    TlsClientAuth,
};
use oidc_types::client_credentials::{
    ClientCredential, ClientSecretCredential, ClientSecretJWTCredential, CredentialError,
    JWTCredential, PrivateKeyJWTCredential, SelfSignedTLSClientAuthCredential,
    TLSClientAuthCredential,
};

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
    #[error("Error parsing body params, {:?}", .0)]
    ParseBody(#[from] SerdeError),
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
        _config: &OpenIDProviderConfiguration, //TODO: config is here to allow access to future mTLS config
    ) -> Result<Credentials, CredentialsError> {
        let mut credentials = HashMap::new();
        let params: HashMap<String, String> = from_bytes(body_bytes)?;
        let mut client_id = params
            .get("client_id")
            .ok_or(CredentialsError::MissingClientId)
            .and_then(|id| parse_client_id(id));

        if let Ok(id) = client_id {
            let credential = TlsClientAuth(TLSClientAuthCredential::new(id));
            credentials.insert(AuthMethod::TlsClientAuth, credential);
            let credential = SelfSignedTlsClientAuth(SelfSignedTLSClientAuthCredential::new(id));
            credentials.insert(AuthMethod::SelfSignedTlsClientAuth, credential);
        }

        if let Ok(AuthBasic((id, secret))) = AuthBasic::from_headers(headers) {
            let (id, credential) = parse_credential(id, secret)?;

            validate_client_id("Authorization header", &client_id, id)?;
            client_id = Ok(id);
            credentials.insert(AuthMethod::ClientSecretBasic, ClientSecretBasic(credential));
        }
        if let Ok(credential) = ClientSecretCredential::try_from(&params) {
            credentials.insert(AuthMethod::ClientSecretPost, ClientSecretPost(credential));
        }
        if let Ok(credential) = JWTCredential::try_from(&params) {
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
    client_id: String,
    secret: Option<String>,
) -> Result<(ClientID, ClientSecretCredential), CredentialsError> {
    let client_id = parse_client_id(client_id.as_str())?;
    let secret = secret.ok_or(CredentialsError::MissingSecret)?;
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

#[derive(Debug, PartialEq, Eq, Clone)]
struct AuthBasic((String, Option<String>));

impl AuthBasic {
    fn from_headers(headers: &HeaderMap) -> Result<Self, (StatusCode, &'static str)> {
        let authorisation = headers
            .get(AUTHORIZATION)
            .ok_or((StatusCode::BAD_REQUEST, "`Authorization` header is missing"))?
            .to_str()
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "`Authorization` header contains invalid characters",
                )
            })?;

        // Check that its a well-formed basic auth then decode and return
        let split = authorisation.split_once(' ');
        match split {
            Some((name, contents)) if name == "Basic" => decode_basic(contents),
            _ => Err((
                StatusCode::BAD_REQUEST,
                "`Authorization` header must be for basic authentication",
            )),
        }
    }
}

fn decode_basic(input: &str) -> Result<AuthBasic, (StatusCode, &'static str)> {
    const ERR: (StatusCode, &str) = (
        StatusCode::BAD_REQUEST,
        "`Authorization` header's basic authentication was improperly encoded",
    );

    // Decode from base64 into a string
    let decoded = base64::decode(input).map_err(|_| ERR)?;
    let decoded = String::from_utf8(decoded).map_err(|_| ERR)?;

    // Return depending on if password is present
    Ok(AuthBasic(
        if let Some((id, password)) = decoded.split_once(':') {
            (id.to_string(), Some(password.to_string()))
        } else {
            (decoded, None)
        },
    ))
}

impl From<CredentialsError> for OpenIdError {
    fn from(err: CredentialsError) -> Self {
        match err {
            CredentialsError::InvalidClientId(_)
            | CredentialsError::MissingClientId
            | CredentialsError::MissingSecret
            | CredentialsError::MismatchedClientId(_)
            | CredentialsError::ParseBody(_)
            | CredentialsError::CredentialError(_) => OpenIdError::invalid_request(err.to_string()),
        }
    }
}
