use crate::jose::jwe::alg::EncryptionAlgorithm;
use crate::jose::jwe::enc::ContentEncryptionAlgorithm;

#[derive(Debug, Clone)]
pub struct EncryptionData {
    pub alg: EncryptionAlgorithm,
    pub enc: ContentEncryptionAlgorithm,
}
