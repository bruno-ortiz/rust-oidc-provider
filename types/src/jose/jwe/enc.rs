use josekit::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption;
use josekit::jwe::enc::aesgcm::AesgcmJweEncryption;
use josekit::jwe::JweContentEncryption;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::prelude::v1::Result::Err;

use serde::de::{Error, StdError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone)]
pub struct ContentEncryptionAlgorithm(Box<dyn JweContentEncryption>);

impl ContentEncryptionAlgorithm {
    pub fn new(jwe_algorithm: Box<dyn JweContentEncryption>) -> Self {
        ContentEncryptionAlgorithm(jwe_algorithm)
    }
}

impl<A> From<A> for ContentEncryptionAlgorithm
where
    A: JweContentEncryption + 'static,
{
    fn from(alg: A) -> Self {
        ContentEncryptionAlgorithm::new(Box::new(alg))
    }
}

impl Eq for ContentEncryptionAlgorithm {}

impl PartialEq for ContentEncryptionAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.0.name() == other.0.name()
    }
}

impl Serialize for ContentEncryptionAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.name())
    }
}

impl<'de> Deserialize<'de> for ContentEncryptionAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AlgVisitor;

        impl<'de> Visitor<'de> for AlgVisitor {
            type Value = ContentEncryptionAlgorithm;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a valid jwe Algorithm.")
            }

            fn visit_str<E>(self, alg: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match alg {
                    "A128CBC-HS256" => Ok(AescbcHmacJweEncryption::A128cbcHs256.into()),
                    "A192CBC-HS384" => Ok(AescbcHmacJweEncryption::A192cbcHs384.into()),
                    "A256CBC-HS512" => Ok(AescbcHmacJweEncryption::A256cbcHs512.into()),
                    "A128GCM" => Ok(AesgcmJweEncryption::A128gcm.into()),
                    "A192GCM" => Ok(AesgcmJweEncryption::A192gcm.into()),
                    "A256GCM" => Ok(AesgcmJweEncryption::A256gcm.into()),

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
    use crate::jose::jwe::enc::ContentEncryptionAlgorithm;
    use josekit::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption::A128cbcHs256;

    #[test]
    fn test_can_serialize_algorithm() {
        let result =
            serde_json::to_string(&ContentEncryptionAlgorithm::new(Box::new(A128cbcHs256)));

        assert_eq!("\"A128CBC-HS256\"", result.unwrap())
    }

    #[test]
    fn test_can_deserialize_algorithm() {
        let result = serde_json::from_str::<ContentEncryptionAlgorithm>("\"A128CBC-HS256\"");

        assert_eq!(
            ContentEncryptionAlgorithm::new(Box::new(A128cbcHs256)),
            result.unwrap()
        )
    }
}
