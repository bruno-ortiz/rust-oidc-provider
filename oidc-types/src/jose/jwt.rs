use std::error;
use std::fmt::{Debug, Display, Formatter, write};

use base64::DecodeError;
use josekit::{JoseError, jwt};
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{EnumAccess, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use url::Url;

use crate::jose::error::JWTError;

#[derive(Debug)]
pub struct JWT {
    header: JwsHeader,
    payload: JwtPayload,
    signed_repr: String,
}

impl JWT {
    fn decode_no_verify(str_jwt: &str) -> Result<Self, JWTError> {
        let parts: Vec<&str> = str_jwt.split(".").collect();

        if parts.len() != 3 {
            return Err(JWTError::InvalidJwtFormat(str_jwt.to_owned()));
        }

        let header_b64 = base64::decode_config(&parts[0], base64::URL_SAFE_NO_PAD)?;
        let header: Map<String, Value> = serde_json::from_slice(&header_b64)?;
        let header = JwsHeader::from_map(header)?;

        let payload_b64 = base64::decode_config(&parts[1], base64::URL_SAFE_NO_PAD)?;
        let payload: Map<String, Value> = serde_json::from_slice(&payload_b64)?;
        let payload = JwtPayload::from_map(payload)?;

        Ok(JWT {
            header,
            payload,
            signed_repr: str_jwt.to_owned(),
        })
    }
}

impl Serialize for JWT {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
        where
            S: Serializer,
    {
        serializer.serialize_str(&self.signed_repr)
    }
}

impl<'de> Deserialize<'de> for JWT {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
    {
        struct JWSVisitor;
        impl<'de> Visitor<'de> for JWSVisitor {
            type Value = JWT;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("an signed jws string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: Error,
            {
                let jwt = JWT::decode_no_verify(v).map_err(de::Error::custom)?;
                Ok(jwt)
            }
        }
        deserializer.deserialize_str(JWSVisitor)
    }
}

#[cfg(test)]
mod tests {
    use std::format as f;

    use josekit::jws::{JwsAlgorithm, JwsHeader};
    use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm;
    use josekit::jwt;
    use josekit::jwt::JwtPayload;
    use serde::Deserialize;
    use serde_json::Value;
    use uuid::Uuid;

    use crate::jose::jwt::JWT;

    #[test]
    fn test_can_deserialize_jwt() {
        let expected_issuer = "myself";
        let expected_token_type = "JWT";
        let expected_token_id = Uuid::new_v4();

        let mut jwt_header = JwsHeader::new();
        jwt_header.set_token_type(expected_token_type);

        let mut jwt_payload = JwtPayload::new();
        jwt_payload.set_jwt_id(f!("{}", expected_token_id));
        jwt_payload.set_issuer(expected_issuer);

        let encoded_jwt = jwt::encode_unsecured(&jwt_payload, &jwt_header).unwrap();
        let jwt: JWT = serde_json::from_str(&f!("\"{}\"", &encoded_jwt)).unwrap();

        assert_eq!(expected_issuer, jwt.payload.issuer().unwrap());
        assert_eq!(expected_token_type, jwt.header.token_type().unwrap());
        assert_eq!(expected_token_id, Uuid::parse_str(jwt.payload.jwt_id().unwrap()).unwrap());
    }

    #[test]
    fn test_can_serialize_jwt() {
        let expected_issuer = "myself";
        let expected_token_type = "JWT";
        let expected_token_id = Uuid::new_v4();

        let mut jwt_header = JwsHeader::new();
        jwt_header.set_token_type(expected_token_type);

        let mut jwt_payload = JwtPayload::new();
        jwt_payload.set_jwt_id(f!("{}", expected_token_id));
        jwt_payload.set_issuer(expected_issuer);

        let encoded_jwt = jwt::encode_unsecured(&jwt_payload, &jwt_header).unwrap();

        let jwt: JWT = JWT { header: jwt_header, payload: jwt_payload, signed_repr: encoded_jwt.clone() };

        let serialized = serde_json::to_string(&jwt).unwrap();
        assert_eq!(f!("\"{}\"", &encoded_jwt), serialized);
    }
}
