use std::collections::HashSet;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};

use lazy_static::lazy_static;
use serde::Serialize;
use serde::{Deserialize, Serializer};

use crate::response_mode::ResponseMode;
use crate::serialize_to_str;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ResponseTypeValue {
    Code,
    IdToken,
    Token,
    None,
}

impl Display for ResponseTypeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let value = match self {
            ResponseTypeValue::Code => "code",
            ResponseTypeValue::IdToken => "id_token",
            ResponseTypeValue::Token => "token",
            ResponseTypeValue::None => "none",
        };
        write!(f, "{}", value)
    }
}

lazy_static! {
    static ref FRAGMENT_VALUES: Vec<ResponseTypeValue> =
        vec![ResponseTypeValue::IdToken, ResponseTypeValue::Token];
}

#[derive(Debug, Eq, Clone)]
pub struct ResponseType(HashSet<ResponseTypeValue>);

impl ResponseType {
    pub fn new(values: Vec<ResponseTypeValue>) -> Self {
        let values_set: HashSet<_> = values.into_iter().collect();
        ResponseType(values_set)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ResponseTypeValue> {
        self.0.iter()
    }

    pub fn default_response_mode(&self) -> ResponseMode {
        let is_fragment = self.0.iter().any(|rt| FRAGMENT_VALUES.contains(rt));
        if is_fragment {
            ResponseMode::Fragment
        } else {
            ResponseMode::Query
        }
    }
}

impl Hash for ResponseType {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for v in &self.0 {
            v.hash(state)
        }
    }
}

impl PartialEq for ResponseType {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Display for ResponseType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let x = self
            .0
            .iter()
            .map(|rt| rt.to_string())
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{}", x)
    }
}

serialize_to_str!(ResponseType);

#[macro_export]
macro_rules! response_type {
    ($($rt:expr),*) =>{
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push($rt);
            )*
            $crate::response_type::ResponseType::new(temp_vec)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use serde::Serialize;

    use crate::response_type::{ResponseType, ResponseTypeValue};

    #[test]
    fn test_can_join_response_type() {
        let rt = ResponseType::new(vec![ResponseTypeValue::Code, ResponseTypeValue::IdToken]);

        assert_eq!("code id_token", rt.to_string())
    }

    #[test]
    fn test_can_serialize_response_types() {
        #[derive(Serialize)]
        struct Test {
            rt: ResponseType,
        }

        let rt = ResponseType::new(vec![ResponseTypeValue::Code, ResponseTypeValue::IdToken]);

        assert_eq!(
            r#"{"rt":"code id_token"}"#,
            serde_json::to_string(&Test { rt }).unwrap()
        )
    }

    #[test]
    fn test_response_type_hash_are_sort_independent() {
        let mut hasher = DefaultHasher::new();
        let rt1 = response_type!(ResponseTypeValue::Code, ResponseTypeValue::IdToken);
        rt1.hash(&mut hasher);
        let rt1_hash = hasher.finish();

        hasher = DefaultHasher::new();
        let rt2 = response_type!(ResponseTypeValue::IdToken, ResponseTypeValue::Code);
        rt2.hash(&mut hasher);
        let rt2_hash = hasher.finish();
        assert_eq!(rt1_hash, rt2_hash)
    }
}
