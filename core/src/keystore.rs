use anyhow::anyhow;
use derive_builder::Builder;
use josekit::jwk::Jwk;

use oidc_types::auth_method::AuthMethod;
use oidc_types::client::ClientInformation;
use oidc_types::jose::jwk_set::JwkSet;
use crate::configuration::OpenIDProviderConfiguration;

#[derive(Debug, Builder)]
struct SelectOption {
    kid: Option<String>,
    kty: Option<String>,
}

trait KeyStore {
    fn select_for(option: SelectOption) -> Vec<Jwk>;
}

pub struct SymmetricKeyStore {
    jwks: JwkSet,
}

impl SymmetricKeyStore {
    pub fn new(client: &ClientInformation) -> Self {
        let config = OpenIDProviderConfiguration::instance();
        
        let mut algorithms = vec![];
        if client.metadata.token_endpoint_auth_method == AuthMethod::ClientSecretJwt {
            if let Some(alg) = client.metadata.token_endpoint_auth_signing_alg.as_ref() {
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
                jwk.set_key_value(&client.secret);
                jwk.set_key_operations(vec!["sign", "verify"]);
                jwk
            })
            .collect();

        Self {
            jwks: JwkSet::new(keys),
        }
    }
}

pub struct AsymmetricKeystore {
    jwks: JwkSet,
}

impl AsymmetricKeystore {
    pub async fn new(client: &ClientInformation) -> Result<Self, anyhow::Error> {
        let jwks = client.metadata.jwks.as_ref();
        let jwks_uri = client.metadata.jwks_uri.as_ref();
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
}

pub struct ClientKeyStore {
    symmetric: SymmetricKeyStore,
    asymmetric: AsymmetricKeystore,
}

impl ClientKeyStore {
    pub async fn new(client: &ClientInformation) -> anyhow::Result<Self> {
        Ok(Self {
            symmetric: SymmetricKeyStore::new(client),
            asymmetric: AsymmetricKeystore::new(client).await?,
        })
    }
}
