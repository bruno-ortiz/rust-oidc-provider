use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Visitor;
use std::fmt::Formatter;
use std::fmt;
use std::error::Error;
use crate::scopes::types::{Scope, Scopes, SimpleScope, ParameterizedScope};

impl Serialize for SimpleScope {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        serialize_scope(serializer, self)
    }
}

impl Serialize for ParameterizedScope {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        serialize_scope(serializer, self)
    }
}

fn serialize_scope<T: Scope, S: Serializer>(serializer: S, scope: &T) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> {
    serializer.serialize_str(scope.value().as_str())
}

impl<'de> Deserialize<'de> for Scopes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        struct ScopesVisitor;

        impl<'de> Visitor<'de> for ScopesVisitor {
            type Value = Scopes;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("'openid account:42'")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: Error, {
                Ok(v.split(' ').collect::<Vec<&str>>().into())
            }
        }
        deserializer.deserialize_str(ScopesVisitor)
    }
}

impl<'de> Deserialize<'de> for Box<dyn Scope> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        struct ScopeVisitor;

        impl<'de> Visitor<'de> for ScopeVisitor {
            type Value = Box<dyn Scope>;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("'openid or account:42'")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: Error, {
                Ok(v.into())
            }
        }
        deserializer.deserialize_str(ScopeVisitor)
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use crate::scopes::types::{Scopes, SimpleScope, ParameterizedScope, Scope};


    #[test]
    fn test_can_deserialize_scopes() {
        let scopes = Scopes::new_boxed(vec![
            Box::new(SimpleScope::new("xpto")),
            Box::new(ParameterizedScope::new("rnd", "42")),
        ]);

        #[derive(Deserialize)]
        struct MyStruct {
            scopes: Scopes,
        }

        let result = serde_json::from_str::<MyStruct>(r#"{
              "scopes": "xpto rnd:42"
            }"#).unwrap();

        assert_eq!(scopes, result.scopes)
    }

    #[test]
    fn test_can_deserialize_vec_of_scope() {
        let scopes = Scopes::new_boxed(vec![
            Box::new(SimpleScope::new("xpto")),
            Box::new(ParameterizedScope::new("rnd", "42")),
        ]);

        #[derive(Deserialize)]
        struct MyStruct {
            scopes: Vec<Box<dyn Scope>>,
        }

        let result = serde_json::from_str::<MyStruct>(r#"{
              "scopes": ["xpto", "rnd:42"]
            }"#).unwrap();

        assert_eq!(scopes, Scopes::new_boxed(result.scopes))
    }

    #[test]
    fn test_can_deserialize_scopes_from_vec_str() {
        let scopes = Scopes::new(vec!["xpto", "rnd:42"]);

        #[derive(Deserialize)]
        struct MyStruct {
            scopes: Scopes,
        }

        let result = serde_json::from_str::<MyStruct>(r#"{
              "scopes": "xpto rnd:42"
            }"#).unwrap();

        assert_eq!(scopes, result.scopes)
    }
}