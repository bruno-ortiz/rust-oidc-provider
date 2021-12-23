use std::collections::HashSet;
use std::fmt;
use std::fmt::{Display, Formatter};

use serde::Serialize;
use serde::{Deserialize, Serializer};

use crate::response_type::ResponseTypeValue::{Code, IdToken, Token};
use crate::serialize_to_str;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ResponseTypeValue {
    Code,
    IdToken,
    Token,
    None,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ResponseType(HashSet<ResponseTypeValue>);

impl ResponseType {
    pub fn new(values: Vec<ResponseTypeValue>) -> Self {
        let values_set: HashSet<_> = values.into_iter().collect();
        ResponseType(values_set)
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

impl Display for ResponseTypeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let value = match self {
            Code => "code",
            ResponseTypeValue::IdToken => "id_token",
            ResponseTypeValue::Token => "token",
            ResponseTypeValue::None => "none",
        };
        write!(f, "{}", value)
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
}
