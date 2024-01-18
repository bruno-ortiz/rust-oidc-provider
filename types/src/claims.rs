use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::acr;
use crate::acr::Acr;

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimOptions {
    essential: bool,
    value: Option<Value>,
    values: Option<Vec<Value>>,
}

impl ClaimOptions {
    pub fn voluntary(value: Option<Value>, values: Option<Vec<Value>>) -> ClaimOptions {
        Self {
            essential: false,
            value,
            values,
        }
    }

    pub fn essential(value: Option<Value>, values: Option<Vec<Value>>) -> ClaimOptions {
        Self {
            essential: true,
            value,
            values,
        }
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

    pub fn is_essential(&self) -> bool {
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
    #[serde(default)]
    pub userinfo: HashMap<String, Option<ClaimOptions>>,
    #[serde(default)]
    pub id_token: HashMap<String, Option<ClaimOptions>>,
}

impl Claims {
    pub fn handle_acr_values_parameter(&mut self, param: Option<&Acr>) {
        if let Some(acr_values) = param {
            if !self.id_token.contains_key(acr::CLAIM_KEY) {
                let (value, values) = acr_values.to_values();
                let co = ClaimOptions::voluntary(value, values);
                self.id_token.insert(acr::CLAIM_KEY.to_owned(), Some(co));
            }
            if !self.userinfo.contains_key(acr::CLAIM_KEY) {
                let (value, values) = acr_values.to_values();
                let co = ClaimOptions::voluntary(value, values);
                self.userinfo.insert(acr::CLAIM_KEY.to_owned(), Some(co));
            }
        }
    }
}
