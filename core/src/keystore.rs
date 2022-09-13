use anyhow::anyhow;
use derive_builder::Builder;
use josekit::jwk::Jwk;

use oidc_types::auth_method::AuthMethod;
use oidc_types::client::ClientMetadata;
use oidc_types::jose::jwk_set::JwkSet;
use oidc_types::secret::PlainTextSecret;

use crate::configuration::OpenIDProviderConfiguration;

#[derive(Debug, Builder, Default)]
#[builder(setter(into, strip_option))]
pub struct SelectOption {
    #[builder(setter(custom))]
    key_use: String,
    kid: Option<String>,
    kty: Option<String>,
    alg: Option<String>,
    crv: Option<String>,
    operation: Option<String>,
}

impl SelectOptionBuilder {
    pub fn use_sig<T: Into<String>>() -> Self {
        let mut builder = Self::create_empty();
        builder.key_use = Some("sig".into());
        builder
    }

    pub fn use_enc<T: Into<String>>() -> Self {
        let mut builder = Self::create_empty();
        builder.key_use = Some("enc".into());
        builder
    }
}

pub struct KeyStore {
    jwks: JwkSet,
}

impl KeyStore {
    pub fn create_symmetric(secret: &PlainTextSecret, metadata: &ClientMetadata) -> Self {
        let config = OpenIDProviderConfiguration::instance();

        let mut algorithms = vec![];
        if metadata.token_endpoint_auth_method == AuthMethod::ClientSecretJwt {
            if let Some(alg) = metadata.token_endpoint_auth_signing_alg.as_ref() {
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
                jwk.set_key_value(secret);
                jwk.set_key_operations(vec!["sign", "verify"]);
                jwk
            })
            .collect();
        Self {
            jwks: JwkSet::new(keys),
        }
    }

    pub async fn create_asymmetric(metadata: &ClientMetadata) -> Result<Self, anyhow::Error> {
        let jwks = metadata.jwks.as_ref();
        let jwks_uri = metadata.jwks_uri.as_ref();
        if jwks.is_some() && jwks_uri.is_some() {
            return Err(anyhow!("Should not use both jwks and jwks_uri"));
        }
        if let Some(jwks_uri) = jwks_uri {
            let jwks = reqwest::get(jwks_uri.as_str())
                .await?
                .json::<JwkSet>()
                .await?;
            Ok(Self { jwks })
        } else if let Some(jwks) = jwks {
            Ok(Self { jwks: jwks.clone() })
        } else {
            Err(anyhow!("unable to build asymmetric keystore"))
        }
    }

    fn select_for(&self, option: SelectOption) -> Vec<&Jwk> {
        self.jwks
            .iter()
            .filter(move |&key| {
                let mut candidate =
                    option.kty.is_some() && option.kty.as_ref().unwrap() == key.key_type();
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
                    candidate = key.key_operations().is_some()
                        && key.key_operations().unwrap().contains(&&**operation);
                }
                candidate
            })
            .collect()
    }
}

pub struct ClientKeyStore {
    symmetric: KeyStore,
    asymmetric: KeyStore,
}

impl ClientKeyStore {
    pub async fn new(secret: &PlainTextSecret, metadata: &ClientMetadata) -> anyhow::Result<Self> {
        Ok(Self {
            symmetric: KeyStore::create_symmetric(secret, metadata),
            asymmetric: KeyStore::create_asymmetric(metadata).await?,
        })
    }
}
