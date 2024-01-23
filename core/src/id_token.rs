use josekit::jwt::JwtPayload;
use serde::{Deserialize, Serialize};

use oidc_types::client::encryption::EncryptionData;
use oidc_types::jose::error::JWTError;
use oidc_types::jose::jwt2::{EncryptedJWT, SignedJWT, JWT};
use oidc_types::simple_id_token::SimpleIdToken;
use IdTokenError::EncryptingErr;
use JWTError::{KeyNotFound, KeystoreCreation};

use crate::id_token_builder::IdTokenError;
use crate::id_token_builder::IdTokenError::InvalidClient;
use crate::keystore::KeyUse;
use crate::models::client::ClientInformation;

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

    pub async fn encrypt(
        self,
        client: &ClientInformation,
    ) -> Result<IdToken<EncryptedJWT<SignedJWT>>, IdTokenError> {
        let client_metadata = client.metadata();
        if let Some(EncryptionData { alg, enc }) = client_metadata.id_token_encryption_data() {
            let keystore = client
                .keystore(alg)
                .await
                .map_err(|err| EncryptingErr(KeystoreCreation(err)))?;
            let key = keystore
                .select(KeyUse::Enc)
                .alg(enc.name())
                .first()
                .ok_or_else(|| EncryptingErr(KeyNotFound("id_token_encryption".to_owned())))?;
            let encrypted = self.0.encrypt(key, enc).map_err(EncryptingErr)?;
            Ok(IdToken(encrypted))
        } else {
            Err(InvalidClient(
                "Missing encryption alg or enc data".to_owned(),
            ))
        }
    }

    pub async fn return_or_encrypt_simple_id_token(
        self,
        client: &ClientInformation,
    ) -> Result<SimpleIdToken, IdTokenError> {
        if client.encrypt_id_token() {
            let encrypted_id_token = self.encrypt(client).await?;
            Ok(SimpleIdToken::new(encrypted_id_token.serialized()))
        } else {
            Ok(SimpleIdToken::new(self.serialized()))
        }
    }
}

impl IdToken<EncryptedJWT<SignedJWT>> {
    pub fn serialized(self) -> String {
        self.0.serialized_owned()
    }
}
