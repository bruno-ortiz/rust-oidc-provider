use std::future::Future;

use thiserror::Error;
use x509_parser::error::X509Error;
use x509_parser::nom;
use x509_parser::pem::Pem;

use oidc_types::certificate::CertificateThumbprint;
use oidc_types::client::ClientID;
use oidc_types::jose::error::JWTError;
use oidc_types::jose::jwt2::{SignedJWT, JWT};
use oidc_types::jose::Algorithm;
use oidc_types::secret::{PlainTextSecret, MIN_SECRET_LEN};
use ClientCredential::*;

use crate::client_credentials::{
    ClientSecretCredential, ClientSecretJWTCredential, JWTCredential, PrivateKeyJWTCredential,
    SelfSignedTLSClientAuthCredential, TLSClientAuthCredential,
};
use crate::configuration::OpenIDProviderConfiguration;
use crate::keystore::KeyUse;
use crate::models::client::{AuthenticatedClient, ClientInformation};
use crate::services::keystore::KeystoreService;
use crate::validate_required_claim;

#[derive(Debug, Error)]
pub enum ClientAuthenticationError {
    #[error("Invalid secret '{}'", .0)]
    InvalidSecret(PlainTextSecret),
    #[error("Cannot authenticate client with the provided certificate")]
    InvalidCertificateAuth,
    #[error("Cannot parse provided certificate to x509 format")]
    InvalidCertificate(#[from] nom::Err<X509Error>),
    #[error("Missing certificate in request. Looked at header: {}", .0)]
    MissingCertificate(&'static str),
    #[error("Invalid authentication method")]
    InvalidAuthMethod,
    #[error("Invalid jwt credential: {:?}, err: {}", .0, .1)]
    InvalidAssertion(SignedJWT, #[source] JWTError),
    #[error("Unable to fetch keystore for user auth")]
    Keystore(#[source] anyhow::Error),
    #[error("Unable to fetch jwk from keystore")]
    Jwk,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub trait ClientAuthenticator {
    fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> impl Future<Output = Result<AuthenticatedClient, ClientAuthenticationError>> + Send;
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

impl ClientAuthenticator for ClientCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        match self {
            ClientSecretBasic(inner) => {
                inner.authenticate(provider, keystore_service, client).await
            }
            ClientSecretPost(inner) => inner.authenticate(provider, keystore_service, client).await,
            ClientSecretJwt(inner) => inner.authenticate(provider, keystore_service, client).await,
            PrivateKeyJwt(inner) => inner.authenticate(provider, keystore_service, client).await,
            TlsClientAuth(inner) => inner.authenticate(provider, keystore_service, client).await,
            SelfSignedTlsClientAuth(inner) => {
                inner.authenticate(provider, keystore_service, client).await
            }
            None => Ok(AuthenticatedClient::new(client, Option::None)),
        }
    }
}

impl ClientAuthenticator for ClientSecretCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        _keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let (secret, certificate) = self.consume();

        if let Some(client_secret) = client.secret() {
            if secret.len() < MIN_SECRET_LEN || client_secret != secret.as_str() {
                return Err(ClientAuthenticationError::InvalidSecret(secret.into()));
            }
            authenticated_client(provider, client, certificate.as_ref())
        } else {
            Err(ClientAuthenticationError::InvalidAuthMethod)
        }
    }
}

impl ClientAuthenticator for ClientSecretJWTCredential {
    //noinspection DuplicatedCode
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let (jwt_credential, certificate) = self.credential();
        authenticate_client_jwt(
            provider,
            keystore_service,
            client,
            jwt_credential,
            certificate,
        )
        .await
    }
}

impl ClientAuthenticator for PrivateKeyJWTCredential {
    //noinspection DuplicatedCode
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let (jwt_credential, certificate) = self.credential();
        authenticate_client_jwt(
            provider,
            keystore_service,
            client,
            jwt_credential,
            certificate,
        )
        .await
    }
}

impl ClientAuthenticator for TLSClientAuthCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        _keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let mtls_config = provider.mtls();
        let pem = self
            .certificate()
            .ok_or(ClientAuthenticationError::MissingCertificate(
                mtls_config.certificate_header(),
            ))?;
        let cert = pem.parse_x509()?;
        let certificate_validator = mtls_config.certificate_validator();
        if !certificate_validator(&cert, &client) {
            return Err(ClientAuthenticationError::InvalidCertificateAuth);
        }
        Ok(AuthenticatedClient::new(
            client,
            Some(CertificateThumbprint::from(cert)),
        ))
    }
}

impl ClientAuthenticator for SelfSignedTLSClientAuthCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let pem = self
            .certificate()
            .ok_or(ClientAuthenticationError::MissingCertificate(
                provider.mtls().certificate_header(),
            ))?;
        let cert = pem.parse_x509()?;
        let keystore = keystore_service
            .asymmetric_keystore(&client)
            .await
            .map_err(ClientAuthenticationError::Internal)?;
        let thumbprint = CertificateThumbprint::from(cert);
        let key = keystore
            .select(Option::None)
            .thumbprint(&thumbprint)
            .first();
        if key.is_some() {
            Ok(AuthenticatedClient::new(client, Some(thumbprint)))
        } else {
            Err(ClientAuthenticationError::InvalidCertificateAuth)
        }
    }
}

async fn authenticate_client_jwt(
    provider: &OpenIDProviderConfiguration,
    keystore_service: &KeystoreService,
    client: ClientInformation,
    jwt_credential: JWTCredential,
    certificate: Option<Pem>,
) -> Result<AuthenticatedClient, ClientAuthenticationError> {
    let jwt = jwt_credential.assertion();
    let alg = jwt.alg().ok_or_else(|| {
        ClientAuthenticationError::InvalidAssertion(jwt.clone(), JWTError::JWTAlgorithmNotFound)
    })?;
    if !provider
        .token_endpoint_auth_signing_alg_values_supported()
        .contains(&alg)
    {
        return Err(ClientAuthenticationError::InvalidAssertion(
            jwt.clone(),
            JWTError::InvalidJWTAlgorithm(format!(
                "alg header {} not supported by the provider",
                alg.name()
            )),
        ));
    }
    if let Some(auth_alg) = client.metadata().token_endpoint_auth_signing_alg.as_ref() {
        if alg != *auth_alg {
            return Err(ClientAuthenticationError::InvalidAssertion(
                jwt,
                JWTError::InvalidJWTAlgorithm(format!(
                    "alg header {} differs from the algorithm registered for the client: {}",
                    alg.name(),
                    client.id()
                )),
            ));
        }
    }
    let keystore = keystore_service
        .keystore(&client, &alg)
        .await
        .map_err(ClientAuthenticationError::Keystore)?;
    let key = keystore
        .select(Some(KeyUse::Sig))
        .kid(jwt.kid().map(ToOwned::to_owned))
        .alg(alg.name())
        .first()
        .ok_or(ClientAuthenticationError::Jwk)?;

    jwt.verify(key)
        .map_err(|err| ClientAuthenticationError::InvalidAssertion(jwt.clone(), err))?;

    validate_jwt(provider, jwt, client.id())?;
    authenticated_client(provider, client, certificate.as_ref())
}

fn authenticated_client(
    provider: &OpenIDProviderConfiguration,
    client: ClientInformation,
    certificate: Option<&Pem>,
) -> Result<AuthenticatedClient, ClientAuthenticationError> {
    if client.metadata().tls_client_certificate_bound_access_tokens {
        let pem = certificate.ok_or(ClientAuthenticationError::MissingCertificate(
            provider.mtls().certificate_header(),
        ))?;
        let cert = pem.parse_x509()?;
        Ok(AuthenticatedClient::new(
            client,
            Some(CertificateThumbprint::from(cert)),
        ))
    } else {
        Ok(AuthenticatedClient::new(client, Option::None))
    }
}

fn validate_jwt(
    provider: &OpenIDProviderConfiguration,
    signed_jwt: SignedJWT,
    client_id: ClientID,
) -> Result<(), ClientAuthenticationError> {
    validate_required_claim!(issuer, signed_jwt, client_id);
    validate_required_claim!(subject, signed_jwt, client_id);
    let expected_audience = provider
        .issuer()
        .inner()
        .join(provider.routes().token)
        .map_err(|err| ClientAuthenticationError::Internal(err.into()))?;
    validate_required_claim!(audience, signed_jwt, contains, expected_audience);
    //TODO: add checks for jti (uniqueness)
    Ok(())
}

mod macros {
    #[macro_export]
    macro_rules! validate_required_claim {
        (
            $claim_name:ident,
            $jwt:ident,
            $expected:expr
        ) => {
            // Checking if the claim exists
            if let Some(claim_value) = $jwt.payload().$claim_name() {
                if claim_value.as_bytes() != $expected.as_ref() {
                    return Err(ClientAuthenticationError::InvalidAssertion(
                        $jwt.clone(), // Ensure you pass 'signed_jwt' into the macro
                        JWTError::InvalidJwtFormat(format!("Invalid {}", stringify!($claim_name))),
                    ));
                }
            } else {
                return Err(ClientAuthenticationError::InvalidAssertion(
                    $jwt.clone(),
                    JWTError::InvalidJwtFormat(format!("missing {}", stringify!($claim_name))),
                ));
            }
        };

        (
            $claim_name:ident,
            $jwt:ident,
            $contains: ident,
            $expected:expr
        ) => {
            // Checking if the claim exists
            if let Some(claim_value) = $jwt.payload().$claim_name() {
                if !claim_value.$contains(&$expected.as_ref()) {
                    return Err(ClientAuthenticationError::InvalidAssertion(
                        $jwt.clone(), // Ensure you pass 'signed_jwt' into the macro
                        JWTError::InvalidJwtFormat(format!("Invalid {}", stringify!($claim_name))),
                    ));
                }
            } else {
                return Err(ClientAuthenticationError::InvalidAssertion(
                    $jwt.clone(),
                    JWTError::InvalidJwtFormat(format!("missing {}", stringify!($claim_name))),
                ));
            }
        };
    }
}
