use anyhow::anyhow;

use oidc_types::client::encryption::EncryptionData;
use oidc_types::jose::error::JWTError;
use oidc_types::jose::jws::SigningAlgorithm;
use oidc_types::jose::jwt2::{EncryptedJWT, SignedJWT};
use oidc_types::jose::Algorithm;
use oidc_types::subject::Subject;
use oidc_types::subject_type::SubjectType;

use crate::configuration::OpenIDProviderConfiguration;
use crate::jwt::GenericJWT;
use crate::keystore::KeyUse;
use crate::models::client::ClientInformation;
use crate::pairwise::PairwiseError;
use crate::services::keystore::KeystoreService;

pub(crate) fn resolve_sub(
    provider: &OpenIDProviderConfiguration,
    subject: &Subject,
    client: &ClientInformation,
) -> Result<Subject, PairwiseError> {
    if client.metadata().subject_type == SubjectType::Pairwise {
        let pairwise_resolver = provider.pairwise_resolver();

        Ok(pairwise_resolver
            .calculate_pairwise_identifier(provider, subject, client)?
            .into_subject())
    } else {
        Ok(subject.clone())
    }
}

pub(crate) async fn encrypt(
    keystore_service: &KeystoreService,
    signed_jwt: SignedJWT,
    client: &ClientInformation,
    enc_config: &EncryptionData<'_>,
) -> anyhow::Result<EncryptedJWT<SignedJWT>> {
    let keystore = keystore_service.keystore(client, enc_config.alg).await?;
    let encryption_key = keystore
        .select(Some(KeyUse::Enc))
        .alg(enc_config.alg.name())
        .first()
        .ok_or_else(|| anyhow!("Missing signing key"))?;
    let encrypted_user_info = signed_jwt.encrypt(encryption_key, enc_config.enc)?;
    Ok(encrypted_user_info)
}

pub(crate) fn get_jose_algorithm(jwt: &str) -> Result<Option<SigningAlgorithm>, JWTError> {
    GenericJWT::parse_alg(jwt)
}
