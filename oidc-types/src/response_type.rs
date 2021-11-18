use crate::serialize_to_str;
use serde::Serialize;
use serde::{Deserialize, Serializer};
use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ResponseTypeValue {
    Code,
    IdToken,
    Token,
    None,
}

#[derive(Debug)]
pub struct ResponseType(Vec<ResponseTypeValue>);

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
            ResponseTypeValue::Code => "code",
            ResponseTypeValue::IdToken => "id_token",
            ResponseTypeValue::Token => "token",
            ResponseTypeValue::None => "none",
        };
        write!(f, "{}", value)
    }
}

serialize_to_str!(ResponseType);

#[cfg(test)]
mod tests {
    use crate::response_type::{ResponseType, ResponseTypeValue};
    use serde::Serialize;

    #[test]
    fn test_can_join_response_type() {
        let rt = ResponseType(vec![ResponseTypeValue::Code, ResponseTypeValue::IdToken]);

        assert_eq!("code id_token", rt.to_string())
    }

    #[test]
    fn test_can_serialize_response_types() {
        #[derive(Serialize)]
        struct Test {
            rt: ResponseType,
        }

        let rt = ResponseType(vec![ResponseTypeValue::Code, ResponseTypeValue::IdToken]);

        assert_eq!(
            r#"{"rt":"code id_token"}"#,
            serde_json::to_string(&Test { rt }).unwrap()
        )
    }
}
