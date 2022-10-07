use crate::jose::jwt2::{EncryptedJWT, SignedJWT};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum UserInfo {
    Normal(HashMap<String, Value>),
    Signed(SignedJWT),
    Encrypted(EncryptedJWT<SignedJWT>),
}
