use std::sync::Arc;

use cached::proc_macro::cached;
use derive_builder::Builder;
use josekit::jwk::Jwk;
use thiserror::Error;

use oidc_types::auth_method::AuthMethod;
use oidc_types::client::ClientID;
use oidc_types::jose::jwk_set::JwkSet;

use crate::configuration::OpenIDProviderConfiguration;
use crate::models::client::ClientInformation;

#[derive(Debug, Copy, Clone)]
pub enum KeyUse {
    Sig,
    Enc,
}

#[derive(Debug, Builder)]
#[builder(setter(into, strip_option))]
pub struct SelectOption<'a> {
    #[builder(setter(custom))]
    keystore: &'a KeyStore,
    #[builder(setter(custom))]
    key_use: String,
    #[builder(default)]
    kid: Option<String>,
    #[builder(default)]
    kty: Option<String>,
    #[builder(default)]
    alg: Option<String>,
    #[builder(default)]
    crv: Option<String>,
    #[builder(default)]
    operation: Option<String>,
}

impl<'a> SelectOptionBuilder<'a> {
    fn use_sig(keystore: &'a KeyStore) -> Self {
        let mut builder = SelectOptionBuilder::create_empty();
        builder.keystore = Some(keystore);
        builder.key_use = Some("sig".into());
        builder
    }

    fn use_enc(keystore: &'a KeyStore) -> Self {
        let mut builder = SelectOptionBuilder::create_empty();
        builder.keystore = Some(keystore);
        builder.key_use = Some("enc".into());
        builder
    }

    pub fn find(&self) -> Vec<&'a Jwk> {
        let opts = self.build().expect("Should always be constructed");
        opts.keystore
            .jwks
            .iter()
            .filter(move |&key| select_predicate(key, &opts))
            .collect()
    }

    pub fn first(&self) -> Option<&'a Jwk> {
        let opts = self.build().expect("Should always be constructed");
        self.keystore
            .expect("Should always be set")
            .jwks
            .iter()
            .find(move |&key| select_predicate(key, &opts))
    }
}

#[derive(Debug, Error)]
pub enum KeyStoreError {
    #[error("Should not use both jwks and jwks_uri")]
    DualJwkSet,
    #[error("Failed to load jwks from jwks_uri")]
    Load(#[from] reqwest::Error),
    #[error("No jwks or jwks_uri set at client")]
    Unset,
}

#[derive(Debug, Clone, Default)]
pub struct KeyStore {
    jwks: JwkSet,
}

impl KeyStore {
    pub fn new(jwks: JwkSet) -> Self {
        Self { jwks }
    }

    pub fn select(&self, key_use: KeyUse) -> SelectOptionBuilder {
        match key_use {
            KeyUse::Sig => SelectOptionBuilder::use_sig(self),
            KeyUse::Enc => SelectOptionBuilder::use_enc(self),
        }
    }

    pub fn inner(&self) -> &JwkSet {
        &self.jwks
    }
}

#[cached(
    key = "ClientID",
    convert = r#"{ client.id() }"#,
    time = 300,
    size = 1000
)]
pub fn create_symmetric(client: &ClientInformation) -> Arc<KeyStore> {
    let config = OpenIDProviderConfiguration::instance();

    let mut algorithms = vec![];
    if client.metadata().token_endpoint_auth_method == AuthMethod::ClientSecretJwt {
        if let Some(alg) = client.metadata().token_endpoint_auth_signing_alg.as_ref() {
            algorithms.push(alg.clone());
        } else {
            let mut algs = config
                .token_endpoint_auth_signing_alg_values_supported()
                .iter()
                .filter(|&it| it.is_symmetric())
                .cloned()
                .collect();
            algorithms.append(&mut algs);
        }
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

#[cached(
    key = "ClientID",
    convert = r#"{ client.id() }"#,
    result = true,
    time = 300,
    size = 1000
)]
pub async fn create_asymmetric(client: &ClientInformation) -> Result<Arc<KeyStore>, KeyStoreError> {
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

fn select_predicate(key: &Jwk, option: &SelectOption) -> bool {
    let mut candidate = option.kty.is_some() && option.kty.as_ref().unwrap() == key.key_type();
    if let Some(kid) = &option.kid {
        candidate = key.key_id().is_some() && key.key_id().as_ref().unwrap() == kid;
    }
    if let Some(alg) = &option.alg {
        candidate = key.algorithm().is_some() && key.algorithm().unwrap() == alg;
    }
    if let Some(u) = key.key_use() {
        candidate = u == option.key_use;
    }
    if let Some(crv) = &option.crv {
        candidate = key.curve().is_some() && key.curve().unwrap() == crv;
    }
    if let Some(operation) = &option.operation {
        candidate =
            key.key_operations().is_some() && key.key_operations().unwrap().contains(&&**operation);
    }
    candidate
}
