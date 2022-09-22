use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimOptions {
    essential: bool,
    value: Option<Value>,
    values: Option<Vec<Value>>,
}

impl ClaimOptions {
    pub fn voluntary() -> ClaimOptions {
        Self::default()
    }

    pub fn validate(&self, value: &Value) -> bool {
        if self.essential && self.value.is_some() {
            let expected = self.value.as_ref().unwrap();
            if expected != value {
                return false;
            }
        }
        if self.essential && self.values.is_some() {
            let expected = self.values.as_ref().unwrap();
            if !expected.contains(value) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    #[serde(deserialize_with = "deserialize_null_default")]
    pub userinfo: HashMap<String, ClaimOptions>,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub id_token: HashMap<String, ClaimOptions>,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<HashMap<String, T>, D::Error>
where
    T: Default + Deserialize<'de>,
    D: Deserializer<'de>,
{
    let opt: HashMap<String, Option<T>> = HashMap::deserialize(deserializer)?;
    let result = opt
        .into_iter()
        .map(|(key, value)| (key, value.unwrap_or_default()))
        .collect();
    Ok(result)
}
