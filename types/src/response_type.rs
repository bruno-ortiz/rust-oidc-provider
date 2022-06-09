use indexmap::IndexSet;

use std::fmt;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use lazy_static::lazy_static;
use serde::de::{Unexpected, Visitor};
use serde::{de, Deserialize, Serializer};
use serde::{Deserializer, Serialize};
use thiserror::Error;

use crate::response_mode::ResponseMode;
use crate::serialize_to_str;

#[macro_export]
macro_rules! response_type {
    ($($rt:expr),*) =>{
        {
            let mut temp_vec = vec![];
            $(
                temp_vec.push($rt);
            )*
            $crate::response_type::ResponseType::new(temp_vec)
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Flow {
    Code,
    Implicit,
    Hybrid,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Copy, Clone, Ord, PartialOrd)]
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

#[derive(Error, Debug)]
#[error("Error parsing response type value {}.", .0)]
pub struct ParseError(String);

impl FromStr for ResponseTypeValue {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "code" => Ok(ResponseTypeValue::Code),
            "id_token" => Ok(ResponseTypeValue::IdToken),
            "token" => Ok(ResponseTypeValue::Token),
            "none" => Ok(ResponseTypeValue::None),
            _ => Err(ParseError(s.to_owned())),
        }
    }
}

lazy_static! {
    static ref FRAGMENT_VALUES: Vec<ResponseTypeValue> =
        vec![ResponseTypeValue::IdToken, ResponseTypeValue::Token];
    pub static ref CODE_FLOW: ResponseType = response_type![ResponseTypeValue::Code];
    pub static ref ID_TOKEN_FLOW: ResponseType = response_type![ResponseTypeValue::IdToken];
    pub static ref TOKEN_FLOW: ResponseType = response_type![ResponseTypeValue::Token];
    pub static ref CODE_ID_TOKEN_FLOW: ResponseType =
        response_type![ResponseTypeValue::Code, ResponseTypeValue::IdToken];
    pub static ref CODE_ID_TOKEN_TOKEN_FLOW: ResponseType = response_type![
        ResponseTypeValue::Code,
        ResponseTypeValue::IdToken,
        ResponseTypeValue::Token
    ];
    pub static ref ID_TOKEN_TOKEN_FLOW: ResponseType =
        response_type![ResponseTypeValue::IdToken, ResponseTypeValue::Token];
    pub static ref CODE_TOKEN_FLOW: ResponseType =
        response_type![ResponseTypeValue::Code, ResponseTypeValue::Token];
}

#[derive(Debug, Eq, Clone)]
pub struct ResponseType(IndexSet<ResponseTypeValue>);

impl ResponseType {
    pub fn new(mut values: Vec<ResponseTypeValue>) -> Self {
        values.sort();
        let values_set: IndexSet<_> = values.into_iter().collect();
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

    pub fn flow(&self) -> Flow {
        if *self == *CODE_FLOW {
            Flow::Code
        } else if *self == *CODE_ID_TOKEN_FLOW
            || *self == *CODE_TOKEN_FLOW
            || *self == *CODE_ID_TOKEN_TOKEN_FLOW
            || *self == *ID_TOKEN_TOKEN_FLOW
        {
            Flow::Hybrid
        } else {
            Flow::Implicit
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

impl<'de> Deserialize<'de> for ResponseType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ResponseTypeVisitor;

        impl<'de> Visitor<'de> for ResponseTypeVisitor {
            type Value = ResponseType;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("'code id_token'")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let response_type_vec: Result<Vec<ResponseTypeValue>, ParseError> =
                    v.split(' ').map(ResponseTypeValue::from_str).collect();
                match response_type_vec {
                    Ok(response_type_vec) => Ok(ResponseType::new(response_type_vec)),
                    Err(err) => Err(de::Error::invalid_value(
                        Unexpected::Str(&err.0),
                        &ResponseTypeVisitor,
                    )),
                }
            }
        }
        deserializer.deserialize_str(ResponseTypeVisitor)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use serde::{Deserialize, Serialize};

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
    fn test_can_deserialize_response_types() {
        #[derive(Deserialize)]
        struct Test {
            rt: ResponseType,
        }

        let rt = ResponseType::new(vec![ResponseTypeValue::Code, ResponseTypeValue::IdToken]);
        let expected = Test { rt };
        let actual: Test = serde_json::from_str(r#"{"rt":"code id_token"}"#).unwrap();

        assert_eq!(expected.rt, actual.rt)
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
