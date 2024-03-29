use derive_builder::Builder;
use josekit::jwk::Jwk;
use oidc_types::certificate::CertificateThumbprint;
use oidc_types::jose::jwk_ext::JwkExt;
use thiserror::Error;

use oidc_types::jose::jwk_set::{JwkSet, PublicJwkSet};

use crate::macros::true_or_return;

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
    #[builder(default, setter(strip_option = false))]
    kid: Option<String>,
    #[builder(default)]
    kty: Option<String>,
    #[builder(default)]
    alg: Option<String>,
    #[builder(default)]
    crv: Option<String>,
    #[builder(default)]
    thumbprint: Option<&'a CertificateThumbprint>,
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

    fn new(keystore: &'a KeyStore) -> Self {
        let mut builder = SelectOptionBuilder::create_empty();
        builder.keystore = Some(keystore);
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
        opts.keystore
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

    pub fn empty() -> Self {
        Self {
            jwks: JwkSet::new(vec![]),
        }
    }

    pub fn select(&self, key_use: Option<KeyUse>) -> SelectOptionBuilder {
        match key_use {
            Some(KeyUse::Sig) => SelectOptionBuilder::use_sig(self),
            Some(KeyUse::Enc) => SelectOptionBuilder::use_enc(self),
            None => SelectOptionBuilder::new(self),
        }
    }

    pub fn public(&self) -> PublicJwkSet {
        PublicJwkSet::new(&self.jwks)
    }
}

fn select_predicate(key: &Jwk, option: &SelectOption) -> bool {
    let mut candidate = option.kty.is_some() && option.kty.as_ref().unwrap() == key.key_type();
    if let Some(kid) = &option.kid {
        true_or_return!(
            candidate = key.key_id().is_some() && key.key_id().as_ref().unwrap() == kid
        );
    }
    if let Some(alg) = &option.alg {
        true_or_return!(candidate = key.algorithm().is_some() && key.algorithm().unwrap() == alg);
    }
    if let Some(u) = key.key_use() {
        true_or_return!(candidate = u == option.key_use);
    }
    if let Some(crv) = &option.crv {
        true_or_return!(candidate = key.curve().is_some() && key.curve().unwrap() == crv);
    }
    if let Some(operation) = &option.operation {
        true_or_return!(
            candidate = if let Some(key_op) = key.key_operations() {
                key_op.contains(&&**operation)
            } else {
                false
            }
        );
    }
    if let Some(thumbprint) = &option.thumbprint {
        true_or_return!(
            candidate = if let Some(key_thumbprint) = key.x509_certificate_sha256_thumbprint_b64() {
                *thumbprint == key_thumbprint
            } else {
                false
            }
        );
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwk::alg::ec::EcCurve;

    #[test]
    fn test_keystore_select_by_key_use_works() {
        let keystore = get_keystore();
        let keys = keystore.select(Some(KeyUse::Enc)).find();
        assert_eq!(keys.len(), 2)
    }

    #[test]
    fn test_keystore_select_works() {
        let keystore = get_keystore();
        let keys = keystore
            .select(Some(KeyUse::Enc))
            .kid(Some("ec-key".to_string()))
            .find();
        assert_eq!(keys.len(), 0)
    }

    fn get_keystore() -> KeyStore {
        let mut ec_key = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        ec_key.set_key_id("ec-key");
        ec_key.set_key_use("sig");
        let mut ec_key_enc = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        ec_key_enc.set_key_id("ec-key-enc");
        ec_key_enc.set_key_use("enc");
        let mut rsa_key = Jwk::generate_rsa_key(512).unwrap();
        rsa_key.set_key_id("rsa-key");
        rsa_key.set_key_use("enc");
        let jwk_set = JwkSet::new(vec![ec_key, ec_key_enc, rsa_key]);
        KeyStore::new(jwk_set)
    }
}
