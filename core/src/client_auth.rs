use async_trait::async_trait;
use thiserror::Error;

use oidc_types::client::{AuthenticatedClient, ClientInformation};
use oidc_types::client_credentials::{
    ClientCredential, ClientSecretCredential, ClientSecretJWTCredential, PrivateKeyJWTCredential,
    SelfSignedTLSClientAuthCredential, TLSClientAuthCredential,
};
use oidc_types::secret::PlainTextSecret;
use ClientCredential::*;

use crate::configuration::OpenIDProviderConfiguration;

#[derive(Debug, Error)]
pub enum ClientAuthenticationError {
    #[error("Invalid secret {}", .0)]
    InvalidSecret(PlainTextSecret),
}

#[async_trait]
pub trait ClientAuthenticator {
    async fn authenticate(
        self,
        config: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError>;
}

#[async_trait]
impl ClientAuthenticator for ClientCredential {
    async fn authenticate(
        self,
        config: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        match self {
            ClientSecretBasic(inner) => inner.authenticate(config, client).await,
            ClientSecretPost(inner) => inner.authenticate(config, client).await,
            ClientSecretJwt(inner) => inner.authenticate(config, client).await,
            PrivateKeyJwt(inner) => inner.authenticate(config, client).await,
            TlsClientAuth(inner) => inner.authenticate(config, client).await,
            SelfSignedTlsClientAuth(inner) => inner.authenticate(config, client).await,
            None => Ok(AuthenticatedClient::new(client)),
        }
    }
}

#[async_trait]
impl ClientAuthenticator for ClientSecretCredential {
    async fn authenticate(
        self,
        _config: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let secret = PlainTextSecret::from(self.secret());
        if client.secret == secret {
            Ok(AuthenticatedClient::new(client))
        } else {
            Err(ClientAuthenticationError::InvalidSecret(secret))
        }
    }
}

#[async_trait]
impl ClientAuthenticator for ClientSecretJWTCredential {
    async fn authenticate(
        self,
        config: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        todo!()
    }
}

#[async_trait]
impl ClientAuthenticator for PrivateKeyJWTCredential {
    async fn authenticate(
        self,
        config: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        todo!()
    }
}

#[async_trait]
impl ClientAuthenticator for TLSClientAuthCredential {
    async fn authenticate(
        self,
        config: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        todo!()
    }
}

#[async_trait]
impl ClientAuthenticator for SelfSignedTLSClientAuthCredential {
    async fn authenticate(
        self,
        config: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        todo!()
    }
}
