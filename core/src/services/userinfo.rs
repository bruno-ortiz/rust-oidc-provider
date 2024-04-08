use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use derive_new::new;
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;
use serde_json::Value;

use oidc_types::jose::jws::{JwsHeaderExt, SigningAlgorithm};
use oidc_types::jose::jwt2::SignedJWT;
use oidc_types::jose::{Algorithm, JwtPayloadExt};
use oidc_types::userinfo::UserInfo;

use crate::claims::get_userinfo_claims;
use crate::client::retrieve_client_info;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::keystore::KeyUse;
use crate::models::access_token::AccessToken;
use crate::models::client::ClientInformation;
use crate::models::token::{ActiveToken, Token};
use crate::profile::ProfileData;
use crate::services::keystore::KeystoreService;
use crate::utils::encrypt;

#[derive(new)]
pub struct UserInfoService {
    provider: Arc<OpenIDProviderConfiguration>,
    keystore_service: Arc<KeystoreService>,
}

impl UserInfoService {
    pub async fn get_user_info(
        &self,
        at: ActiveToken<AccessToken>,
    ) -> Result<UserInfo, OpenIdError> {
        let grant = at.grant();
        let client = retrieve_client_info(&self.provider, grant.client_id())
            .await?
            .ok_or_else(|| {
                OpenIdError::server_error(anyhow!("Grant contains invalid client id"))
            })?;

        let profile = ProfileData::get(&self.provider, grant, &client)
            .await
            .map_err(OpenIdError::server_error)?;
        let claims: HashMap<&str, Value> = get_userinfo_claims(
            &self.provider,
            &profile,
            grant.claims().as_ref(),
            at.scopes(),
        )?
        .into_iter()
        .map(|(k, v)| (k, v.to_owned()))
        .collect();

        let result: UserInfo;
        if let Some(ref alg) = client.metadata().userinfo_signed_response_alg {
            let signed = self
                .sign_user_info(claims, &client, alg)
                .map_err(OpenIdError::server_error)?;
            if let Some(enc_config) = client.metadata().userinfo_encryption_data() {
                let encrypted = encrypt(&self.keystore_service, signed, &client, &enc_config)
                    .await
                    .map_err(OpenIdError::server_error)?;
                result = UserInfo::Encrypted(encrypted)
            } else {
                result = UserInfo::Signed(signed)
            }
        } else {
            let claims = claims.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
            result = UserInfo::Normal(claims)
        }
        Ok(result)
    }

    fn sign_user_info(
        &self,
        claims: HashMap<&str, Value>,
        client: &ClientInformation,
        alg: &SigningAlgorithm,
    ) -> anyhow::Result<SignedJWT> {
        let keystore = self.keystore_service.server_keystore(client, alg);
        let signing_key = keystore
            .select(Some(KeyUse::Sig))
            .alg(alg.name())
            .first()
            .ok_or_else(|| anyhow!("Missing signing key"))?;
        let header = JwsHeader::from_key(signing_key);
        let payload = JwtPayload::from_hash_map(claims);
        let signed_user_info = SignedJWT::new(header, payload, signing_key)?;
        Ok(signed_user_info)
    }
}
