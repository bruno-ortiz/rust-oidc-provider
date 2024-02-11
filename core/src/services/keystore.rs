use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use josekit::jwk::Jwk;
use quick_cache::sync::Cache;
use quick_cache::GuardResult;
use sha2::{Digest, Sha256, Sha384, Sha512};

use oidc_types::auth_method::AuthMethod;
use oidc_types::client::{ClientID, ClientMetadata};
use oidc_types::jose::jwk_set::JwkSet;
use oidc_types::jose::{Algorithm, SizableAlgorithm};
use oidc_types::secret::PlainTextSecret;

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

    fn create_symmetric(&self, client: &ClientInformation) -> Arc<KeyStore> {
        let client_metadata = client.metadata();
        if let Some(client_secret) = client.secret() {
            let signing_keys = self.create_signing_keys(client_metadata, client_secret);
            let enc_keys = self.create_encryption_keys(client_metadata, client_secret);
            let cek_keys = self.create_content_encryption_keys(client_metadata, client_secret);
            Arc::new(KeyStore::new(JwkSet::new(
                [signing_keys, enc_keys, cek_keys].concat(),
            )))
        } else {
            Arc::new(KeyStore::empty())
        }
    }

    fn create_signing_keys(
        &self,
        client_metadata: &ClientMetadata,
        client_secret: &PlainTextSecret,
    ) -> Vec<Jwk> {
        let mut signing_algorithms = HashSet::new();
        if client_metadata.token_endpoint_auth_method == AuthMethod::ClientSecretJwt {
            if let Some(alg) = client_metadata.token_endpoint_auth_signing_alg.as_ref() {
                if alg.is_symmetric() {
                    signing_algorithms.insert(alg.clone());
                }
            } else {
                self.provider
                    .token_endpoint_auth_signing_alg_values_supported()
                    .iter()
                    .filter(|&it| it.is_symmetric())
                    .cloned()
                    .for_each(|alg| {
                        signing_algorithms.insert(alg);
                    });
            }
        }
        [
            Some(&client_metadata.id_token_signed_response_alg),
            client_metadata.userinfo_signed_response_alg.as_ref(),
            Some(&client_metadata.authorization_signed_response_alg),
            client_metadata.request_object_signing_alg.as_ref(),
        ]
        .into_iter()
        .flatten()
        .filter(|alg| alg.is_symmetric())
        .cloned()
        .for_each(|alg| {
            signing_algorithms.insert(alg);
        });

        if client_metadata.request_object_signing_alg.is_none() {
            self.provider
                .request_object_signing_alg_values_supported()
                .iter()
                .filter(|&it| it.is_symmetric())
                .cloned()
                .for_each(|alg| {
                    signing_algorithms.insert(alg);
                });
        }

        let keys = signing_algorithms
            .into_iter()
            .map(|alg| {
                let mut jwk = Jwk::new("oct");
                jwk.set_algorithm(alg.name());
                jwk.set_key_use("sig");
                jwk.set_key_value(client_secret);
                jwk.set_key_operations(vec!["sign", "verify"]);
                jwk
            })
            .collect();
        keys
    }

    fn create_encryption_keys(
        &self,
        client_metadata: &ClientMetadata,
        client_secret: &PlainTextSecret,
    ) -> Vec<Jwk> {
        let mut algorithms = HashSet::new();
        [
            client_metadata.id_token_encrypted_response_alg.as_ref(),
            client_metadata.userinfo_encrypted_response_alg.as_ref(),
            client_metadata
                .authorization_encrypted_response_alg
                .as_ref(),
            client_metadata.request_object_encryption_alg.as_ref(),
        ]
        .into_iter()
        .flatten()
        .filter(|alg| alg.is_symmetric())
        .cloned()
        .for_each(|alg| {
            algorithms.insert(alg);
        });

        self.provider
            .request_object_encryption_alg_values_supported()
            .iter()
            .flatten()
            .filter(|&it| it.is_symmetric())
            .cloned()
            .for_each(|alg| {
                algorithms.insert(alg);
            });

        create_enc_jwk(client_secret, algorithms)
    }

    fn create_content_encryption_keys(
        &self,
        client_metadata: &ClientMetadata,
        client_secret: &PlainTextSecret,
    ) -> Vec<Jwk> {
        let mut algorithms = HashSet::new();
        [
            client_metadata.id_token_encrypted_response_enc.as_ref(),
            client_metadata.userinfo_encrypted_response_enc.as_ref(),
            client_metadata
                .authorization_encrypted_response_enc
                .as_ref(),
            client_metadata.request_object_encryption_enc.as_ref(),
        ]
        .into_iter()
        .flatten()
        .filter(|alg| alg.is_symmetric())
        .cloned()
        .for_each(|alg| {
            algorithms.insert(alg);
        });
        create_enc_jwk(client_secret, algorithms)
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

fn create_enc_jwk<A: SizableAlgorithm>(
    client_secret: &PlainTextSecret,
    algorithms: HashSet<A>,
) -> Vec<Jwk> {
    algorithms
        .into_iter()
        .filter_map(|alg| {
            alg.length().map(|len| {
                let mut jwk = Jwk::new("oct");
                jwk.set_algorithm(alg.name());
                jwk.set_key_use("enc");
                jwk.set_key_value(derive_encryption_key(client_secret.as_ref(), len));
                jwk
            })
        })
        .collect()
}

fn derive_encryption_key(secret: &str, length: usize) -> Vec<u8> {
    match length {
        len if len <= 32 => Sha256::digest(secret)[0..length].to_vec(),
        len if len <= 48 => Sha384::digest(secret)[0..length].to_vec(),
        len if len <= 64 => Sha512::digest(secret)[0..length].to_vec(),
        _ => panic!("Unsupported symmetric encryption key derivation"),
    }
}
