use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use josekit::jwk::Jwk;
use quick_cache::sync::Cache;
use quick_cache::GuardResult;

use oidc_types::auth_method::AuthMethod;
use oidc_types::client::ClientID;
use oidc_types::jose::jwk_set::JwkSet;
use oidc_types::jose::Algorithm;

use crate::configuration::OpenIDProviderConfiguration;
use crate::keystore::{KeyStore, KeyStoreError};
use crate::models::client::ClientInformation;

const DEFAULT_CACHE_CAPACITY: usize = 1000;

pub struct KeystoreService {
    provider: Arc<OpenIDProviderConfiguration>,
    cache: Cache<ClientID, Arc<KeyStore>>,
}

impl KeystoreService {
    pub fn new(provider: Arc<OpenIDProviderConfiguration>) -> Self {
        Self {
            provider,
            cache: Cache::new(DEFAULT_CACHE_CAPACITY),
        }
    }

    pub fn server_keystore(
        &self,
        client: &ClientInformation,
        alg: &impl Algorithm,
    ) -> Arc<KeyStore> {
        if alg.is_symmetric() {
            self.symmetric_keystore(client)
        } else {
            self.provider.keystore()
        }
    }

    pub async fn keystore(
        &self,
        client: &ClientInformation,
        alg: &impl Algorithm,
    ) -> anyhow::Result<Arc<KeyStore>> {
        if alg.is_symmetric() {
            Ok(self.symmetric_keystore(client))
        } else {
            self.asymmetric_keystore(client).await
        }
    }

    fn symmetric_keystore(&self, client: &ClientInformation) -> Arc<KeyStore> {
        match self
            .cache
            .get_value_or_guard(&client.id(), Some(Duration::from_millis(100)))
        {
            GuardResult::Value(value) => value,
            GuardResult::Guard(placeholder) => {
                let keystore = self.create_symmetric(client);
                match placeholder.insert(keystore.clone()) {
                    Ok(_) => keystore,
                    Err(k) => k,
                }
            }
            GuardResult::Timeout => self.create_symmetric(client),
        }
    }

    async fn asymmetric_keystore(
        &self,
        client: &ClientInformation,
    ) -> anyhow::Result<Arc<KeyStore>> {
        match self.cache.get_value_or_guard_async(&client.id()).await {
            Ok(keystore) => Ok(keystore),
            Err(placeholder) => {
                let keystore = self.create_asymmetric(client).await?;
                match placeholder.insert(keystore.clone()) {
                    Ok(_) => Ok(keystore),
                    Err(k) => Ok(k),
                }
            }
        }
    }

    //TODO: finish implementation of symmetric keystore
    fn create_symmetric(&self, client: &ClientInformation) -> Arc<KeyStore> {
        let mut algorithms = HashSet::new();
        let client_metadata = client.metadata();
        if client_metadata.token_endpoint_auth_method == AuthMethod::ClientSecretJwt {
            if let Some(alg) = client_metadata.token_endpoint_auth_signing_alg.as_ref() {
                if alg.is_symmetric() {
                    algorithms.insert(alg.clone());
                }
            } else {
                let algs = self
                    .provider
                    .token_endpoint_auth_signing_alg_values_supported()
                    .iter()
                    .filter(|&it| it.is_symmetric())
                    .cloned()
                    .collect::<Vec<_>>();
                for alg in algs {
                    algorithms.insert(alg);
                }
            }
        }
        if client_metadata.id_token_signed_response_alg.is_symmetric() {
            algorithms.insert(client_metadata.id_token_signed_response_alg.clone());
        }
        let keys = algorithms
            .into_iter()
            .map(|alg| {
                let mut jwk = Jwk::new("oct");
                jwk.set_algorithm(alg.name());
                jwk.set_key_use("sig");
                jwk.set_key_value(client.secret());
                jwk.set_key_operations(vec!["sign", "verify"]);
                jwk
            })
            .collect();
        Arc::new(KeyStore::new(JwkSet::new(keys)))
    }

    async fn create_asymmetric(
        &self,
        client: &ClientInformation,
    ) -> Result<Arc<KeyStore>, KeyStoreError> {
        let jwks = client.metadata().jwks.as_ref();
        let jwks_uri = client.metadata().jwks_uri.as_ref();
        if jwks.is_some() && jwks_uri.is_some() {
            return Err(KeyStoreError::DualJwkSet);
        }
        if let Some(jwks_uri) = jwks_uri {
            let jwks = reqwest::get(jwks_uri.as_str())
                .await?
                .json::<JwkSet>()
                .await?;
            Ok(Arc::new(KeyStore::new(jwks)))
        } else if let Some(jwks) = jwks {
            Ok(Arc::new(KeyStore::new(jwks.clone())))
        } else {
            Err(KeyStoreError::Unset)
        }
    }
}
