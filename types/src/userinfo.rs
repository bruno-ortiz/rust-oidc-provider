use crate::jose::jwt::JWT;
use serde_json::Value;
use std::collections::HashMap;

pub enum UserInfo {
    Normal(HashMap<String, Value>),
    Signed(JWT),
    Encrypted(String),
}
