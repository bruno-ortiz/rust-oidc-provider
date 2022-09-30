use std::ops::Deref;
use std::str;
use std::str::FromStr;

use josekit::jwe::{JweContext, JweHeader};
use josekit::jws::JwsAlgorithm;
use josekit::jwt::alg::unsecured::UnsecuredJwsAlgorithm;
use josekit::jwt::JwtPayload;
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use oidc_types::jose::error::JWTError;
use oidc_types::jose::jwk_ext::JwkExt;
use oidc_types::jose::jws::SigningAlgorithm;
use oidc_types::jose::jwt2::{EncryptedJWT, SignedJWT, JWT};

use crate::keystore::KeyUse;
use crate::models::client::ClientInformation;

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

    pub fn parse(jwt: &str, client: &ClientInformation) -> Result<Self, JWTError> {
        let parts = jwt.split('.').collect::<Vec<_>>();
        if parts.len() == 3 {
            Ok(GenericJWT::Signed(SignedJWT::decode_no_verify(jwt)?))
        } else if parts.len() == 5 {
            let header =
                JweHeader::from_bytes(parts[0].as_bytes()).map_err(JWTError::HeaderParseError)?;
            let alg = header
                .algorithm()
                .and_then(|it| SigningAlgorithm::from_str(it).ok())
                .ok_or(JWTError::JWKAlgorithmNotFound)?;
            let keystore = client.server_keystore(&alg);
            let jwk = keystore
                .select(KeyUse::Enc)
                .alg(alg.name())
                .kid(header.key_id().map(String::from))
                .first()
                .ok_or(JWTError::KeyNotFound("JWE decryption".to_owned()))?;
            let jwe = JweContext::new();
            let decrypter = jwk
                .get_decrypter()
                .map_err(JWTError::DecrypterCreationError)?;
            let (content, header) = jwe
                .deserialize_compact(jwt, &*decrypter)
                .map_err(JWTError::DecryptError)?;

            match header.content_type() {
                Some(cty) if cty == "JWT" => {
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
    pub async fn validate(
        jwt: &GenericJWT,
        client: &ClientInformation,
    ) -> Result<ValidJWT<GenericJWT>, JWTError> {
        let valid = match jwt {
            GenericJWT::Encrypted(_) => ValidJWT(jwt.clone()),
            GenericJWT::Signed(ref inner) => {
                validate_signature(client, inner).await?;
                ValidJWT(jwt.clone())
            }
            GenericJWT::SignedAndEncrypted(ref inner) => {
                validate_signature(client, inner.signed_payload()).await?;
                ValidJWT(jwt.clone())
            }
        };
        Ok(valid)
    }
}

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

async fn validate_signature(client: &ClientInformation, jwt: &SignedJWT) -> Result<(), JWTError> {
    let alg = jwt.alg().ok_or(JWTError::JWKAlgorithmNotFound)?;
    if alg.name() != UnsecuredJwsAlgorithm::None.name() {
        let keystore = client
            .keystore(&alg)
            .await
            .map_err(JWTError::KeystoreCreation)?;
        let jwk = keystore
            .select(KeyUse::Sig)
            .alg(alg.name())
            .kid(jwt.kid().map(ToOwned::to_owned))
            .first()
            .ok_or_else(|| JWTError::KeyNotFound("jwt signature validation".to_owned()))?;
        jwt.verify(jwk)
    } else {
        Ok(())
    }
}
