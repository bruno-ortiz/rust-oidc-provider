use std::fmt::Formatter;

use josekit::jws::JwsHeader;
use josekit::jwt;
use josekit::jwt::JwtPayload;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{EnumAccess, Error, MapAccess, SeqAccess, Visitor};
use url::Url;

pub struct JWS {
    header: JwsHeader,
    payload: JwtPayload,
    signed_repr: String,
}

impl Serialize for JWS {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
        where
            S: Serializer,
    {
        serializer.serialize_str(&self.signed_repr)
    }
}

impl<'de> Deserialize<'de> for JWS {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        struct JWSVisitor;
        impl<'de> Visitor<'de> for JWSVisitor {
            type Value = JWS;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("an signed jws string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: Error {
                let (payload, header) = jwt::decode_unsecured(v)
                    .map_err(de::Error::custom)?;
                Ok(JWS {
                    header,
                    payload,
                    signed_repr: v.to_string(),
                })
            }
        }
        deserializer.deserialize_str(JWSVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::jose::jws::JWS;
    use serde::Deserialize;

    #[test]
    fn test_can_deserialize_jws() {
        let raw_jws = r#"
        {
            "jws":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        }
        "#;

        #[derive(Deserialize)]
        struct JWSHolder{
            jws:JWS,
        }
        match serde_json::from_str::<JWSHolder>(raw_jws) {
            Ok(jws) => {}
            Err(err) => { panic!("test failed! Err: {}", err) }
        }
    }
}