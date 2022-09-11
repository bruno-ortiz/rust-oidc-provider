use std::fmt;
use std::fmt::{Display, Formatter};
use std::prelude::v1::Result::Err;

use josekit::jws::JwsAlgorithm;
use josekit::jws::*;
use serde::de::{Error, StdError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone)]
pub struct SigningAlgorithm(Box<dyn JwsAlgorithm>);

impl SigningAlgorithm {
    pub fn new(jws_algorithm: Box<dyn JwsAlgorithm>) -> Self {
        SigningAlgorithm(jws_algorithm)
    }
}

impl<A> From<A> for SigningAlgorithm
where
    A: JwsAlgorithm + 'static,
{
    fn from(alg: A) -> Self {
        SigningAlgorithm::new(Box::new(alg))
    }
}

impl PartialEq for SigningAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.0.name() == other.0.name()
    }
}

impl Eq for SigningAlgorithm {}

impl Serialize for SigningAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.name())
    }
}

impl<'de> Deserialize<'de> for SigningAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AlgVisitor;

        impl<'de> Visitor<'de> for AlgVisitor {
            type Value = SigningAlgorithm;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a valid jws algorithm.")
            }

            fn visit_str<E>(self, alg: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match alg {
                    "HS256" => Ok(SigningAlgorithm::new(Box::new(HS256))),
                    "HS384" => Ok(SigningAlgorithm::new(Box::new(HS384))),
                    "HS512" => Ok(SigningAlgorithm::new(Box::new(HS512))),
                    "RS256" => Ok(SigningAlgorithm::new(Box::new(RS256))),
                    "RS384" => Ok(SigningAlgorithm::new(Box::new(RS384))),
                    "RS512" => Ok(SigningAlgorithm::new(Box::new(RS512))),
                    "PS256" => Ok(SigningAlgorithm::new(Box::new(PS256))),
                    "PS384" => Ok(SigningAlgorithm::new(Box::new(PS384))),
                    "PS512" => Ok(SigningAlgorithm::new(Box::new(PS512))),
                    "ES256" => Ok(SigningAlgorithm::new(Box::new(ES256))),
                    "ES256K" => Ok(SigningAlgorithm::new(Box::new(ES256K))),
                    "ES384" => Ok(SigningAlgorithm::new(Box::new(ES384))),
                    "ES512" => Ok(SigningAlgorithm::new(Box::new(ES512))),
                    "EdDSA" => Ok(SigningAlgorithm::new(Box::new(EdDSA))),
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
    use josekit::jws::ES256;

    use crate::jose::jws::SigningAlgorithm;

    #[test]
    fn test_can_serialize_algorithm() {
        let result = serde_json::to_string(&SigningAlgorithm::new(Box::new(ES256)));

        assert_eq!("\"ES256\"", result.unwrap())
    }

    #[test]
    fn test_can_deserialize_algorithm() {
        let result = serde_json::from_str::<SigningAlgorithm>("\"ES256\"");

        assert_eq!(SigningAlgorithm::new(Box::new(ES256)), result.unwrap())
    }
}
