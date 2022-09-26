use josekit::jwe::{JweContext, JweHeader};
use josekit::jwk::Jwk;
use josekit::jwt::JwtPayload;
use serde::{Deserialize, Serialize};

use oidc_types::jose::jwe::JweHeaderExt;
use oidc_types::jose::jwk_ext::JwkExt;
use oidc_types::jose::jwt2::{EncryptedJWT, SignedJWT, JWT};

use crate::id_token_builder::IdTokenError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdToken<T>(T)
where
    T: JWT;

impl IdToken<SignedJWT> {
    pub fn new(inner: SignedJWT) -> Self {
        IdToken(inner)
    }

    pub fn payload(&self) -> &JwtPayload {
        self.0.payload()
    }

    pub fn serialized(self) -> String {
        self.0.serialized_owned()
    }

    pub fn encrypt(
        self,
        key: &Jwk,
        content_encryption: impl Into<String>,
    ) -> Result<IdToken<EncryptedJWT<SignedJWT>>, IdTokenError> {
        let encrypter = key.get_encrypter().map_err(IdTokenError::EncryptingErr)?;

        let header = JweHeader::from_key(key, content_encryption, true);
        let payload = self.0.serialized().as_bytes();
        let ctx = JweContext::new();
        let encrypted = ctx
            .serialize_compact(payload, &header, &*encrypter)
            .map_err(IdTokenError::EncryptingErr)?;
        Ok(IdToken(EncryptedJWT::new_signed(header, self.0, encrypted)))
    }
}
