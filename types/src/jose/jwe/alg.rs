use std::fmt;
use std::fmt::{Display, Formatter};
use std::prelude::v1::Result::Err;

use josekit::jwe::alg::aesgcmkw::AesgcmkwJweAlgorithm;
use josekit::jwe::alg::aeskw::AeskwJweAlgorithm;
use josekit::jwe::alg::direct::DirectJweAlgorithm;
use josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm;
use josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweAlgorithm;
use josekit::jwe::alg::rsaes::RsaesJweAlgorithm;
use josekit::jwe::JweAlgorithm;
use serde::de::{Error, StdError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::jose::Algorithm;

#[derive(Debug, Clone)]
pub struct EncryptionAlgorithm(Box<dyn JweAlgorithm>);

impl EncryptionAlgorithm {
    pub fn new(jwe_algorithm: Box<dyn JweAlgorithm>) -> Self {
        EncryptionAlgorithm(jwe_algorithm)
    }

    pub fn name(&self) -> &str {
        self.0.name()
    }
}

impl Algorithm for EncryptionAlgorithm {
    fn is_symmetric(&self) -> bool {
        let name = self.0.name();
        name.starts_with("PBES2") || (name.starts_with('A') && name.ends_with("KW"))
    }
}

impl<A> From<A> for EncryptionAlgorithm
where
    A: JweAlgorithm + 'static,
{
    fn from(alg: A) -> Self {
        EncryptionAlgorithm::new(Box::new(alg))
    }
}

impl Eq for EncryptionAlgorithm {}

impl PartialEq for EncryptionAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.0.name() == other.0.name()
    }
}

impl Serialize for EncryptionAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.name())
    }
}

impl<'de> Deserialize<'de> for EncryptionAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AlgVisitor;

        impl<'de> Visitor<'de> for AlgVisitor {
            type Value = EncryptionAlgorithm;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a valid jwe Algorithm.")
            }

            fn visit_str<E>(self, alg: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match alg {
                    "dir" => Ok(DirectJweAlgorithm::Dir.into()),
                    "A128GCMKW" => Ok(AesgcmkwJweAlgorithm::A128gcmkw.into()),
                    "A192GCMKW" => Ok(AesgcmkwJweAlgorithm::A192gcmkw.into()),
                    "A256GCMKW" => Ok(AesgcmkwJweAlgorithm::A256gcmkw.into()),
                    "A128KW" => Ok(AeskwJweAlgorithm::A128kw.into()),
                    "A192KW" => Ok(AeskwJweAlgorithm::A192kw.into()),
                    "A256KW" => Ok(AeskwJweAlgorithm::A256kw.into()),
                    "ECDH-ES" => Ok(EcdhEsJweAlgorithm::EcdhEs.into()),
                    "ECDH-ES+A128KW" => Ok(EcdhEsJweAlgorithm::EcdhEsA128kw.into()),
                    "ECDH-ES+A192KW" => Ok(EcdhEsJweAlgorithm::EcdhEsA192kw.into()),
                    "ECDH-ES+A256KW" => Ok(EcdhEsJweAlgorithm::EcdhEsA256kw.into()),
                    "PBES2-HS256+A128KW" => Ok(Pbes2HmacAeskwJweAlgorithm::Pbes2Hs256A128kw.into()),
                    "PBES2-HS384+A192KW" => Ok(Pbes2HmacAeskwJweAlgorithm::Pbes2Hs384A192kw.into()),
                    "PBES2-HS512+A256KW" => Ok(Pbes2HmacAeskwJweAlgorithm::Pbes2Hs512A256kw.into()),
                    "RSA-OAEP" => Ok(RsaesJweAlgorithm::RsaOaep.into()),
                    "RSA-OAEP-256" => Ok(RsaesJweAlgorithm::RsaOaep256.into()),
                    "RSA-OAEP-384" => Ok(RsaesJweAlgorithm::RsaOaep384.into()),
                    "RSA-OAEP-512" => Ok(RsaesJweAlgorithm::RsaOaep512.into()),

                    _ => Err(Error::custom(format!("Unsupported algorithm {}", alg))),
                }
            }
        }
        deserializer.deserialize_str(AlgVisitor)
    }
}

#[derive(Debug)]
struct DeserializeError(String);

impl Display for DeserializeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl StdError for DeserializeError {}

#[cfg(test)]
mod tests {
    use josekit::jwe::RSA_OAEP;

    use crate::jose::jwe::alg::EncryptionAlgorithm;

    #[test]
    fn test_can_serialize_algorithm() {
        let result = serde_json::to_string(&EncryptionAlgorithm::new(Box::new(RSA_OAEP)));

        assert_eq!("\"RSA-OAEP\"", result.unwrap())
    }

    #[test]
    fn test_can_deserialize_algorithm() {
        let result = serde_json::from_str::<EncryptionAlgorithm>("\"RSA-OAEP\"");

        assert_eq!(
            EncryptionAlgorithm::new(Box::new(RSA_OAEP)),
            result.unwrap()
        )
    }
}
