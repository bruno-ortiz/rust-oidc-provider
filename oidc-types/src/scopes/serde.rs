use std::error::Error;
use std::fmt;
use std::fmt::Formatter;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::scopes::types::{Scope, Scopes};
use crate::serialize_to_str;

impl Serialize for Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.value().as_str())
    }
}

serialize_to_str!(Scopes);

impl<'de> Deserialize<'de> for Scopes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScopesVisitor;

        impl<'de> Visitor<'de> for ScopesVisitor {
            type Value = Scopes;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("'openid account:42'")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(v.split(' ').collect::<Vec<&str>>().into())
            }
        }
        deserializer.deserialize_str(ScopesVisitor)
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScopeVisitor;

        impl<'de> Visitor<'de> for ScopeVisitor {
            type Value = Scope;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("'openid or account:42'")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(v.into())
            }
        }
        deserializer.deserialize_str(ScopeVisitor)
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::scopes::types::{Scope, Scopes};

    #[test]
    fn test_can_deserialize_scopes() {
        let scopes = Scopes::from_vec(vec![
            Scope::SimpleScope("xpto".to_owned()),
            Scope::ParameterizedScope("rnd".to_owned(), "42".to_owned()),
        ]);

        #[derive(Deserialize)]
        struct MyStruct {
            scopes: Scopes,
        }

        let result = serde_json::from_str::<MyStruct>(
            r#"{
              "scopes": "xpto rnd:42"
            }"#,
        )
        .unwrap();

        assert_eq!(scopes, result.scopes)
    }

    #[test]
    fn test_can_deserialize_vec_of_scope() {
        let scopes = Scopes::from_vec(vec![
            Scope::SimpleScope("xpto".to_owned()),
            Scope::ParameterizedScope("rnd".to_owned(), "42".to_owned()),
        ]);

        #[derive(Deserialize)]
        struct MyStruct {
            scopes: Vec<Scope>,
        }

        let result = serde_json::from_str::<MyStruct>(
            r#"{
              "scopes": ["xpto", "rnd:42"]
            }"#,
        )
        .unwrap();

        assert_eq!(scopes, Scopes::from_vec(result.scopes))
    }

    #[test]
    fn test_can_deserialize_scopes_from_vec_str() {
        let scopes = Scopes::new(vec!["xpto", "rnd:42"]);

        #[derive(Deserialize)]
        struct MyStruct {
            scopes: Scopes,
        }

        let result = serde_json::from_str::<MyStruct>(
            r#"{
              "scopes": "xpto rnd:42"
            }"#,
        )
        .unwrap();

        assert_eq!(scopes, result.scopes)
    }
}
