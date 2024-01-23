use std::collections::HashMap;

use anyhow::anyhow;
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;
use serde_json::Value;
use tracing::error;

use oidc_types::client::encryption::EncryptionData;
use oidc_types::jose::jws::{JwsHeaderExt, SigningAlgorithm};
use oidc_types::jose::jwt2::{EncryptedJWT, SignedJWT};
use oidc_types::jose::JwtPayloadExt;
use oidc_types::userinfo::UserInfo;

use crate::claims::get_userinfo_claims;
use crate::client::retrieve_client_info;
use crate::error::OpenIdError;
use crate::keystore::KeyUse;
use crate::models::access_token::ActiveAccessToken;
use crate::models::client::ClientInformation;
use crate::models::grant::Grant;
use crate::profile::ProfileData;
use crate::utils::encrypt;

pub async fn get_user_info(at: ActiveAccessToken) -> Result<UserInfo, OpenIdError> {
    let grant = Grant::find(at.grant_id())
        .await
        .ok_or_else(|| OpenIdError::invalid_grant("invalid access_token"))?;

    let client = retrieve_client_info(grant.client_id())
        .await
        .ok_or_else(|| OpenIdError::server_error(anyhow!("Grant contains invalid client id")))?;

    let profile = ProfileData::get(&grant, &client)
        .await
        .map_err(OpenIdError::server_error)?;
    let claims: HashMap<&str, Value> =
        get_userinfo_claims(&profile, grant.claims().as_ref(), at.scopes())?
            .into_iter()
            .map(|(k, v)| (k, v.to_owned()))
            .collect();

    let client = retrieve_client_info(grant.client_id())
        .await
        .ok_or_else(|| {
            error!("Trying to retrieve invalid client {}", grant.client_id());
            OpenIdError::server_error(anyhow!("invalid access"))
        })?;
    let result: UserInfo;
    if let Some(ref alg) = client.metadata().userinfo_signed_response_alg {
        let signed = sign_user_info(claims, &client, alg).map_err(OpenIdError::server_error)?;
        if let Some(enc_config) = client.metadata().userinfo_encryption_data() {
            let encrypted = encrypt(signed, &client, &enc_config)
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
    claims: HashMap<&str, Value>,
    client: &ClientInformation,
    alg: &SigningAlgorithm,
) -> anyhow::Result<SignedJWT> {
    let keystore = client.server_keystore(alg);
    let signing_key = keystore
        .select(KeyUse::Sig)
        .alg(alg.name())
        .first()
        .ok_or_else(|| anyhow!("Missing signing key"))?;
    let header = JwsHeader::from_key(signing_key);
    let payload = JwtPayload::from_hash_map(claims);
    let signed_user_info = SignedJWT::new(header, payload, signing_key)?;
    Ok(signed_user_info)
}
