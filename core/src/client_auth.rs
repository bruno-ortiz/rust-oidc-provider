use async_trait::async_trait;
use thiserror::Error;

use oidc_types::secret::{PlainTextSecret, MIN_SECRET_LEN};
use ClientCredential::*;

use crate::client_credentials::{
    ClientCredential, ClientSecretCredential, ClientSecretJWTCredential, PrivateKeyJWTCredential,
    SelfSignedTLSClientAuthCredential, TLSClientAuthCredential,
};
use crate::configuration::OpenIDProviderConfiguration;
use crate::models::client::{AuthenticatedClient, ClientInformation};

#[derive(Debug, Error)]
pub enum ClientAuthenticationError {
    #[error("Invalid secret {}", .0)]
    InvalidSecret(PlainTextSecret),
    #[error("Invalid authentication method")]
    InvalidAuthMethod,
}

#[async_trait]
pub trait ClientAuthenticator {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError>;
}

#[async_trait]
impl ClientAuthenticator for ClientCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let auth_method = client.metadata().token_endpoint_auth_method;
        if !provider
            .token_endpoint_auth_methods_supported()
            .contains(&auth_method)
        {
            return Err(ClientAuthenticationError::InvalidAuthMethod);
        }
        match self {
            ClientSecretBasic(inner) => inner.authenticate(provider, client).await,
            ClientSecretPost(inner) => inner.authenticate(provider, client).await,
            ClientSecretJwt(inner) => inner.authenticate(provider, client).await,
            PrivateKeyJwt(inner) => inner.authenticate(provider, client).await,
            TlsClientAuth(inner) => inner.authenticate(provider, client).await,
            SelfSignedTlsClientAuth(inner) => inner.authenticate(provider, client).await,
            None => Ok(AuthenticatedClient::new(client)),
        }
    }
}

#[async_trait]
impl ClientAuthenticator for ClientSecretCredential {
    async fn authenticate(
        self,
        _provider: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let secret = self.secret();
        if secret.len() < MIN_SECRET_LEN {
            return Err(ClientAuthenticationError::InvalidSecret(secret.into()));
        }
        if let Some(client_secret) = client.secret() {
            if client_secret == secret.as_str() {
                Ok(AuthenticatedClient::new(client))
            } else {
                Err(ClientAuthenticationError::InvalidSecret(secret.into()))
            }
        } else {
            Err(ClientAuthenticationError::InvalidAuthMethod)
        }
    }
}

#[async_trait]
impl ClientAuthenticator for ClientSecretJWTCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        todo!()
    }
}

#[async_trait]
impl ClientAuthenticator for PrivateKeyJWTCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        todo!()
    }
}

#[async_trait]
impl ClientAuthenticator for TLSClientAuthCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        todo!()
    }
}

#[async_trait]
impl ClientAuthenticator for SelfSignedTLSClientAuthCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        todo!()
    }
}
