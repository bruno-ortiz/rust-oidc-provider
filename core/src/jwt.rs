use std::ops::Deref;
use std::str;
use std::str::FromStr;

use josekit::jwe::JweContext;
use josekit::jws::JwsAlgorithm;
use josekit::jwt::alg::unsecured::UnsecuredJwsAlgorithm;
use josekit::jwt::JwtPayload;
use oidc_types::jose::Algorithm;
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use oidc_types::jose::error::JWTError;
use oidc_types::jose::jwk_ext::JwkExt;
use oidc_types::jose::jws::SigningAlgorithm;
use oidc_types::jose::jwt2::{EncryptedJWT, SignedJWT, JWT};

use crate::keystore::{KeyStore, KeyUse};

#[derive(Debug, Clone)]
pub enum GenericJWT {
    Signed(SignedJWT),
    Encrypted(EncryptedJWT<JwtPayload>),
    SignedAndEncrypted(EncryptedJWT<SignedJWT>),
}

impl GenericJWT {
    pub fn alg(&self) -> Option<SigningAlgorithm> {
        match self {
            GenericJWT::Signed(inner) => inner.alg(),
            GenericJWT::SignedAndEncrypted(inner) => inner.signed_payload().alg(),
            GenericJWT::Encrypted(_) => None,
        }
    }

    pub fn parse(jwt: &str, keystore: &KeyStore) -> Result<Self, JWTError> {
        let parts = jwt.split('.').collect::<Vec<_>>();
        if parts.len() == 3 {
            Ok(GenericJWT::Signed(SignedJWT::decode_no_verify(jwt)?))
        } else if parts.len() == 5 {
            let header = EncryptedJWT::<SignedJWT>::decode_header(parts[0])?;
            let alg = header
                .algorithm()
                .and_then(|it| SigningAlgorithm::from_str(it).ok())
                .ok_or(JWTError::JWTAlgorithmNotFound)?;
            let jwk = keystore
                .select(Some(KeyUse::Enc))
                .alg(alg.name())
                .kid(header.key_id().map(String::from))
                .first()
                .ok_or_else(|| JWTError::KeyNotFound("JWE decryption".to_owned()))?;
            let jwe = JweContext::new();
            let decrypter = jwk
                .get_decrypter()
                .map_err(JWTError::DecrypterCreationError)?;
            let (content, header) = jwe
                .deserialize_compact(jwt, &*decrypter)
                .map_err(JWTError::DecryptError)?;

            match header.content_type() {
                Some("JWT") => {
                    let content = str::from_utf8(&content)?;
                    let payload = SignedJWT::decode_no_verify(content)?;
                    Ok(GenericJWT::SignedAndEncrypted(EncryptedJWT::new_signed(
                        header,
                        payload,
                        jwt.to_owned(),
                    )))
                }
                Some(_) | None => {
                    let map: Map<String, Value> = serde_json::from_slice(&content)?;
                    let payload = JwtPayload::from_map(map)?;
                    Ok(GenericJWT::Encrypted(EncryptedJWT::new(
                        header,
                        payload,
                        jwt.to_owned(),
                    )))
                }
            }
        } else {
            Err(JWTError::InvalidJwtFormat(
                "Expected signed or encrypted JWT".to_owned(),
            ))
        }
    }
    pub fn parse_alg(jwt: &str) -> Result<Option<SigningAlgorithm>, JWTError> {
        let parts = jwt.split('.').collect::<Vec<_>>();
        if parts.len() == 3 {
            let header = SignedJWT::decode_header(parts[0])?;
            Ok(header
                .algorithm()
                .map(SigningAlgorithm::from_str)
                .transpose()?)
        } else if parts.len() == 5 {
            let header = EncryptedJWT::<SignedJWT>::decode_header(parts[0])?;
            Ok(header
                .algorithm()
                .map(SigningAlgorithm::from_str)
                .transpose()?)
        } else {
            Err(JWTError::InvalidJwtFormat(format!("Invalid jwt: {}", jwt)))
        }
    }
}

impl JWT for GenericJWT {
    type Header = Map<String, Value>;

    fn header(&self) -> &Self::Header {
        match self {
            GenericJWT::Signed(inner) => inner.header().claims_set(),
            GenericJWT::Encrypted(inner) => inner.header().claims_set(),
            GenericJWT::SignedAndEncrypted(inner) => inner.header().claims_set(),
        }
    }

    fn payload(&self) -> &JwtPayload {
        match self {
            GenericJWT::Signed(inner) => inner.payload(),
            GenericJWT::Encrypted(inner) => inner.payload(),
            GenericJWT::SignedAndEncrypted(inner) => inner.payload(),
        }
    }

    fn serialized(&self) -> &str {
        match self {
            GenericJWT::Signed(inner) => inner.serialized(),
            GenericJWT::Encrypted(inner) => inner.serialized(),
            GenericJWT::SignedAndEncrypted(inner) => inner.serialized(),
        }
    }

    fn serialized_owned(self) -> String {
        match self {
            GenericJWT::Signed(inner) => inner.serialized_owned(),
            GenericJWT::Encrypted(inner) => inner.serialized_owned(),
            GenericJWT::SignedAndEncrypted(inner) => inner.serialized_owned(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidJWT<T>(T)
where
    T: JWT;

impl ValidJWT<GenericJWT> {
    pub fn validate(
        jwt: GenericJWT,
        keystore: &KeyStore,
    ) -> Result<ValidJWT<GenericJWT>, JWTError> {
        let valid = match jwt {
            GenericJWT::Encrypted(_) => ValidJWT(jwt),
            GenericJWT::Signed(ref inner) => {
                validate_signature(keystore, inner)?;
                ValidJWT(jwt)
            }
            GenericJWT::SignedAndEncrypted(ref inner) => {
                validate_signature(keystore, inner.signed_payload())?;
                ValidJWT(jwt)
            }
        };
        Ok(valid)
    }

    pub fn serialized(self) -> String {
        self.0.serialized_owned()
    }
}

impl<T> PartialEq for ValidJWT<T>
where
    T: JWT,
{
    fn eq(&self, other: &Self) -> bool {
        self.0.serialized() == other.0.serialized()
    }
}

impl<T> Eq for ValidJWT<T> where T: JWT {}

impl<T> Deref for ValidJWT<T>
where
    T: JWT,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Serialize for ValidJWT<T>
where
    T: JWT,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.serialized())
    }
}

fn validate_signature(keystore: &KeyStore, jwt: &SignedJWT) -> Result<(), JWTError> {
    let alg = jwt.alg().ok_or(JWTError::JWTAlgorithmNotFound)?;
    if alg.name() != UnsecuredJwsAlgorithm::None.name() {
        let jwk = keystore
            .select(Some(KeyUse::Sig))
            .alg(alg.name())
            .kid(jwt.kid().map(ToOwned::to_owned))
            .first()
            .ok_or_else(|| JWTError::KeyNotFound("jwt signature validation".to_owned()))?;
        jwt.verify(jwk)
    } else {
        Ok(())
    }
}
