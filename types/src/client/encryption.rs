use crate::jose::jwe::alg::EncryptionAlgorithm;
use crate::jose::jwe::enc::ContentEncryptionAlgorithm;

#[derive(Debug, Clone)]
pub struct EncryptionData<'a> {
    pub alg: &'a EncryptionAlgorithm,
    pub enc: &'a ContentEncryptionAlgorithm,
}
