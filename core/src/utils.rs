use crate::configuration::OpenIDProviderConfiguration;
use crate::keystore::KeyUse;
use crate::models::client::ClientInformation;
use crate::pairwise::PairwiseError;
use anyhow::anyhow;
use oidc_types::client::encryption::EncryptionData;
use oidc_types::jose::jwt2::{EncryptedJWT, SignedJWT};
use oidc_types::subject::Subject;
use oidc_types::subject_type::SubjectType;

pub(crate) fn resolve_sub(
    configuration: &OpenIDProviderConfiguration,
    subject: &Subject,
    client: &ClientInformation,
) -> Result<Subject, PairwiseError> {
    if client.metadata().subject_type == SubjectType::Pairwise {
        let pairwise_resolver = configuration.pairwise_resolver();

        Ok(pairwise_resolver
            .calculate_pairwise_identifier(subject, client)?
            .into_subject())
    } else {
        Ok(subject.clone())
    }
}

pub(crate) async fn encrypt(
    signed_jwt: SignedJWT,
    client: &ClientInformation,
    enc_config: &EncryptionData<'_>,
) -> anyhow::Result<EncryptedJWT<SignedJWT>> {
    let keystore = client.keystore(enc_config.alg).await?;
    let encryption_key = keystore
        .select(KeyUse::Enc)
        .alg(enc_config.alg.name())
        .first()
        .ok_or_else(|| anyhow!("Missing signing key"))?;
    let encrypted_user_info = signed_jwt.encrypt(encryption_key, enc_config.enc)?;
    Ok(encrypted_user_info)
}
