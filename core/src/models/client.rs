use std::ops::Deref;
use std::sync::Arc;

use getset::{CopyGetters, Getters};
use time::OffsetDateTime;

use oidc_types::auth_method::AuthMethod;
use oidc_types::client::{ClientID, ClientMetadata};
use oidc_types::grant_type::GrantType;
use oidc_types::identifiable::Identifiable;
use oidc_types::jose::jws::SigningAlgorithm;
use oidc_types::jose::Algorithm;
use oidc_types::secret::HashedSecret;

use crate::configuration::OpenIDProviderConfiguration;
use crate::keystore;
use crate::keystore::KeyStore;

#[derive(Debug, Clone, CopyGetters, Getters)]
pub struct ClientInformation {
    #[get_copy = "pub"]
    id: ClientID,
    #[get_copy = "pub"]
    issue_date: OffsetDateTime,
    #[get = "pub"]
    secret: HashedSecret,
    #[get_copy = "pub"]
    secret_expires_at: Option<OffsetDateTime>,
    #[get = "pub"]
    metadata: ClientMetadata,
}

impl ClientInformation {
    pub fn new(
        id: ClientID,
        issue_date: OffsetDateTime,
        secret: HashedSecret,
        secret_expires_at: Option<OffsetDateTime>,
        metadata: ClientMetadata,
    ) -> Self {
        Self {
            id,
            issue_date,
            secret,
            secret_expires_at,
            metadata,
        }
    }

    pub fn consume_metadata(self) -> ClientMetadata {
        self.metadata
    }

    pub fn server_keystore(
        &self,
        provider: &OpenIDProviderConfiguration,
        alg: &impl Algorithm,
    ) -> Arc<KeyStore> {
        if alg.is_symmetric() {
            self.symmetric_keystore(provider)
        } else {
            provider.keystore()
        }
    }

    pub async fn keystore(
        &self,
        provider: &OpenIDProviderConfiguration,
        alg: &impl Algorithm,
    ) -> anyhow::Result<Arc<KeyStore>> {
        if alg.is_symmetric() {
            Ok(self.symmetric_keystore(provider))
        } else {
            self.asymmetric_keystore().await
        }
    }

    pub fn symmetric_keystore(&self, provider: &OpenIDProviderConfiguration) -> Arc<KeyStore> {
        keystore::create_symmetric(provider, self)
    }

    pub async fn asymmetric_keystore(&self) -> anyhow::Result<Arc<KeyStore>> {
        Ok(keystore::create_asymmetric(self).await?)
    }

    pub fn encrypt_id_token(&self) -> bool {
        self.metadata.id_token_encryption_data().is_some()
    }
}

impl Identifiable<ClientID> for ClientInformation {
    fn id(&self) -> &ClientID {
        &self.id
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedClient(ClientInformation);

impl AuthenticatedClient {
    pub fn new(client: ClientInformation) -> Self {
        Self(client)
    }

    pub fn id(&self) -> ClientID {
        self.0.id
    }

    pub fn allows_grant(&self, grant_type: GrantType) -> bool {
        self.0.metadata.grant_types.contains(&grant_type)
    }
    pub fn auth_method(&self) -> AuthMethod {
        self.0.metadata.token_endpoint_auth_method
    }
    pub fn id_token_signing_alg(&self) -> &SigningAlgorithm {
        &self.0.metadata.id_token_signed_response_alg
    }
}

impl Deref for AuthenticatedClient {
    type Target = ClientInformation;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<ClientInformation> for AuthenticatedClient {
    fn as_ref(&self) -> &ClientInformation {
        &self.0
    }
}
