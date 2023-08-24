use std::collections::HashMap;

use serde::{Deserialize, Serialize};
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

    pub fn essential(&self) -> bool {
        self.essential
    }

    pub fn value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    pub fn values(&self) -> Option<&Vec<Value>> {
        self.values.as_ref()
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    pub userinfo: HashMap<String, Option<ClaimOptions>>,
    pub id_token: HashMap<String, Option<ClaimOptions>>,
}
