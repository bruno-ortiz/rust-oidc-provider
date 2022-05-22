use std::fmt::{Debug, Formatter};

use josekit::jwk::Jwk;
use josekit::jws::{
    EdDSA, JwsHeader, JwsSigner, ES256, ES256K, ES384, ES512, HS256, HS384, HS512, PS256, PS384,
    PS512, RS256, RS384, RS512,
};
use josekit::jwt;
use josekit::jwt::JwtPayload;
use serde::de::{Error, Visitor};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::jose::error::JWTError;

#[derive(Debug, Clone)]
pub struct JWT {
    header: JwsHeader,
    payload: JwtPayload,
    signed_repr: String,
}

impl JWT {
    pub fn new(header: JwsHeader, payload: JwtPayload, key: &Jwk) -> Result<Self, JWTError> {
        let signer = Self::get_signer(key)?;
        let result = jwt::encode_with_signer(&payload, &header, &*signer)
            .map_err(JWTError::JoseCreationError)?;
        Ok(JWT {
            header,
            payload,
            signed_repr: result,
        })
    }

    pub fn encode_string(
        header: JwsHeader,
        payload: JwtPayload,
        key: &Jwk,
    ) -> Result<String, JWTError> {
        let signer = Self::get_signer(key)?;
        let result = jwt::encode_with_signer(&payload, &header, &*signer)
            .map_err(JWTError::JoseCreationError)?;
        Ok(result)
    }

    pub fn decode_no_verify(str_jwt: &str) -> Result<Self, JWTError> {
        let parts: Vec<&str> = str_jwt.split('.').collect();

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

    fn get_signer(key: &Jwk) -> Result<Box<dyn JwsSigner>, JWTError> {
        let alg = &key
            .algorithm()
            .ok_or(JWTError::JWKAlgorithmNotFound)?
            .to_uppercase()[..];

        let signer: Box<dyn JwsSigner> = match alg {
            "ES256" => Box::new(
                ES256
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "ES384" => Box::new(
                ES384
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "ES512" => Box::new(
                ES512
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "ES256K" => Box::new(
                ES256K
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "EDDSA" => Box::new(
                EdDSA
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "RS256" => Box::new(
                RS256
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "RS384" => Box::new(
                RS384
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "RS512" => Box::new(
                RS512
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "PS256" => Box::new(
                PS256
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "PS384" => Box::new(
                PS384
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "PS512" => Box::new(
                PS512
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "HS256" => Box::new(
                HS256
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "HS384" => Box::new(
                HS384
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            "HS512" => Box::new(
                HS512
                    .signer_from_jwk(key)
                    .map_err(JWTError::SignerCreationError)?,
            ),
            _ => unreachable!("should be unreachable"),
        };
        Ok(signer)
    }

    pub fn serialize(&self) -> &str {
        &self.signed_repr
    }

    pub fn serialize_owned(self) -> String {
        self.signed_repr
    }
}

impl Serialize for JWT {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
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

    use josekit::jwk::Jwk;
    use josekit::jws::JwsHeader;
    use josekit::jwt;
    use josekit::jwt::JwtPayload;
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
        assert_eq!(
            expected_token_id,
            Uuid::parse_str(jwt.payload.jwt_id().unwrap()).unwrap()
        );
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

        let jwt: JWT = JWT {
            header: jwt_header,
            payload: jwt_payload,
            signed_repr: encoded_jwt.clone(),
        };

        let serialized = serde_json::to_string(&jwt).unwrap();
        assert_eq!(f!("\"{}\"", &encoded_jwt), serialized);
    }

    #[test]
    fn test_can_create_jwt() {
        let expected_issuer = "myself";
        let expected_token_type = "JWT";
        let expected_token_id = Uuid::new_v4();

        let mut jwt_header = JwsHeader::new();
        jwt_header.set_token_type(expected_token_type);

        let mut jwt_payload = JwtPayload::new();
        jwt_payload.set_jwt_id(f!("{}", expected_token_id));
        jwt_payload.set_issuer(expected_issuer);

        let rsa_key = Jwk::from_bytes(r#"
        {
            "p": "2Z1co6mhAXOtwSb1szKBcHd1jCyddlXr401qp3v_VnRMCoYKxgVSwSbuxOZjhtfKBb_Mc6kE6Je6rqWK_rv6cP0ks1HgPj0tsoY_9CBfxFVqYJNKPg4pN56E2bJNgNi-QbwPjCryHIdFeg_Z6_aH9faEekrCKEUqz8BkOeQgVOU",
            "kty": "RSA",
            "q": "p9JlJzQ95xZ8EV85RpGrd-jNMTj8W481LEEFhzG9LVHftxLLUcRykdxRpWDBGBPzNufLJBta69AGaPh2SUS8wZ2NqXcMSSzS5i6jbG4rMHhm5p7sUCb4WVzgtYNRCWja3IZDOj4okSlwV7fwVNoE0Ss5NLtGxdgowJFtlKoLYD0",
            "d": "cT9-1AtogU18LXHPhlj9XIgi1NaPP6Tzb6QTvEXbdGfmKnf93zdEP_9luEtzQ4iShla7AIeJw_unTw7XYTnHuOmKICRntWuf3Lv11OcHIC6b-bkV7Hn2JwMmLjOtSkVhWWveUh8kcbCcZjACtLCtCkNfVxxyOEuta0rmGKRB7Gv0khxLIVhEafX_Zd6i5FJvB3xy9JCxRQbXwPX6aRva-Rmr3cm6ruwzmpU7aAK9kHU28Q-LNt0s7cehH0QCi4fmMNBIN3_OxPo9madikL9mcH_cBPlrP--jKk6sIjeR-q8Pf4QzgbHn-RvlP2EWSwmgF6R73P2O551iK4De-ifLYQ",
            "e": "AQAB",
            "use": "sig",
            "kid": "r-4-wCX8jS7L5pbXQ-6APrf2O5Go1DOEsJXS8AghDiw",
            "qi": "qmpQ-cleaW7vr7B8XhvPIY3Xn2g2OzsufM0T8HetT60OUIVZddcdxJZffUvTt_U8uajGmiXtStusRJBtOblZuB74NBV8zx5vapow7Ncs3ZK7ThIAM2C8aDjtxiaaALmD6ktqM72OYEDDBJlFO3khvfvmCl0BeK3xhbXR0hCwXBg",
            "dp": "I-JuH1LeiPXBZkN9arJeY-RfDuFgid37Sv0-JCYvYdtFmsqlxiekkNNRtkhjix3UY4RQO5ZYh95VW21S8VSgJLepsKREvR6rhW_b5e7cu-x14T0IlhkRtOk_8QIVA7U6Em7nhW6jhA7OZyVsAxwhKW8gQ2ZGhAt71sxb-qvipP0",
            "alg": "RS256",
            "dq": "jHp-t-lwI99bbYNDQ4IugUo7cQedntrqjKfFA90r2SLe3LV7wm9p5BUDtyadnBUfEwfGsOvBGQHiS74n7b7_Lic_bOq9OwetZocFv38c4g73O_cuIw3r94nag7ZvgCvogI5W-gsMFC8W3iaXo794JstCsJRPcs81lbRmgPoyWZU",
            "n": "jqiAgSrXcqFxYCYXIK9tqxjipf00nLuCpTFKqsrnu5mp8LKZskyZ_fOHntpk_Fkc1twnrRwluptKin8U_d7Cz4S5VqAJkx0CKDDTPImjvpB4VxmiegLT2OCuZK9ZPXOzljZ1yiftvR_JoZDHXf2WawP-W-BvlWOwtsXf6lJOFW39i29PMKwCIMaPfq9FC-8zMtI3o8u0TRKjKgHR1PwKUXyRPo-ImfdorVd-J0mmuJQWeNa-0bECTzuPnaL4x1Lf8QG1IOeZjin7UzgDSsahJyrilV7gSkO9kocZuqvbMRl37OZjg_fHowK19Khq22UBUcTdh9kFwkvi83J_M2EakQ"
        }
        "#).expect("parsed jwk");
        let jwt = JWT::new(jwt_header, jwt_payload, &rsa_key).unwrap();

        assert_eq!(expected_issuer, jwt.payload.issuer().unwrap());
        assert_eq!(expected_token_type, jwt.header.token_type().unwrap());
        assert_eq!(
            expected_token_id,
            Uuid::parse_str(jwt.payload.jwt_id().unwrap()).unwrap()
        );
    }
}
