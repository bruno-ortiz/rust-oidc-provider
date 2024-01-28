use std::fmt::Formatter;
use std::str::FromStr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as base64_engine;
use base64::Engine;
use josekit::jwe::{JweContext, JweHeader};
use josekit::jwk::Jwk;
use josekit::jws::JwsHeader;
use josekit::jwt;
use josekit::jwt::JwtPayload;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::jose::error::JWTError;
use crate::jose::jwe::enc::ContentEncryptionAlgorithm;
use crate::jose::jwe::JweHeaderExt;
use crate::jose::jwk_ext::JwkExt;
use crate::jose::jws::SigningAlgorithm;

pub trait JWT {
    type Header;
    fn header(&self) -> &Self::Header;
    fn payload(&self) -> &JwtPayload;
    fn serialized(&self) -> &str;
    fn serialized_owned(self) -> String;
}

#[derive(Debug, Clone)]
pub struct SignedJWT {
    header: JwsHeader,
    payload: JwtPayload,
    serialized_repr: String,
}

impl SignedJWT {
    pub fn new(header: JwsHeader, payload: JwtPayload, key: &Jwk) -> Result<Self, JWTError> {
        let signer = key.get_signer()?;
        let result = jwt::encode_with_signer(&payload, &header, &*signer)
            .map_err(JWTError::JoseCreationError)?;
        Ok(SignedJWT {
            header,
            payload,
            serialized_repr: result,
        })
    }

    pub fn alg(&self) -> Option<SigningAlgorithm> {
        self.header()
            .algorithm()
            .and_then(|it| SigningAlgorithm::from_str(it).ok())
    }

    pub fn kid(&self) -> Option<&str> {
        self.header().key_id()
    }

    pub fn verify(&self, key: &Jwk) -> Result<(), JWTError> {
        let verifier = key
            .get_verifier()
            .map_err(JWTError::VerifierCreationError)?;
        let jwt_bytes = self.serialized_repr.as_bytes();
        let indexes: Vec<usize> = jwt_bytes
            .iter()
            .enumerate()
            .filter(|(_, b)| **b == b'.')
            .map(|(pos, _)| pos)
            .collect();

        let header_and_payload = &jwt_bytes[..indexes[1]];
        let signature = &jwt_bytes[(indexes[1] + 1)..];
        let decoded_signature = base64_engine.decode(signature)?;
        verifier
            .verify(header_and_payload, &decoded_signature)
            .map_err(JWTError::InvalidSignature)
    }

    pub fn encrypt(
        self,
        key: &Jwk,
        content_encryption: &ContentEncryptionAlgorithm,
    ) -> Result<EncryptedJWT<SignedJWT>, JWTError> {
        let encrypter = key
            .get_encrypter()
            .map_err(JWTError::EncrypterCreationError)?;

        let header = JweHeader::from_key(key, content_encryption.name(), true);
        let payload = self.serialized().as_bytes();
        let ctx = JweContext::new();
        let encrypted = ctx
            .serialize_compact(payload, &header, &*encrypter)
            .map_err(JWTError::EncryptError)?;
        Ok(EncryptedJWT::new_signed(header, self, encrypted))
    }

    pub fn decode_no_verify(input: impl AsRef<str>) -> Result<Self, JWTError> {
        let str_jwt = input.as_ref();
        let parts: Vec<&str> = str_jwt.split('.').collect();

        if parts.len() != 3 {
            return Err(JWTError::InvalidJwtFormat(str_jwt.to_owned()));
        }

        let header_b64 = base64_engine.decode(parts[0])?;
        let header: Map<String, Value> = serde_json::from_slice(&header_b64)?;
        let header = JwsHeader::from_map(header)?;

        let payload_b64 = base64_engine.decode(parts[1])?;
        let payload: Map<String, Value> = serde_json::from_slice(&payload_b64)?;
        let payload = JwtPayload::from_map(payload)?;

        Ok(SignedJWT {
            header,
            payload,
            serialized_repr: str_jwt.to_owned(),
        })
    }

    pub fn decode_header(header_part: impl AsRef<[u8]>) -> Result<JwsHeader, JWTError> {
        let header_b64 = base64_engine.decode(header_part)?;
        let header: Map<String, Value> = serde_json::from_slice(&header_b64)?;
        Ok(JwsHeader::from_map(header)?)
    }
}

impl JWT for SignedJWT {
    type Header = JwsHeader;

    fn header(&self) -> &Self::Header {
        &self.header
    }

    fn payload(&self) -> &JwtPayload {
        &self.payload
    }

    fn serialized(&self) -> &str {
        &self.serialized_repr
    }

    fn serialized_owned(self) -> String {
        self.serialized_repr
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedJWT<P> {
    header: JweHeader,
    payload: P,
    serialized_repr: String,
}

impl<P> EncryptedJWT<P> {
    pub fn decode_header(input: impl AsRef<[u8]>) -> Result<JweHeader, JWTError> {
        let header_b64 = base64_engine.decode(input)?;
        let header: Map<String, Value> = serde_json::from_slice(&header_b64)?;
        Ok(JweHeader::from_map(header)?)
    }
}

impl EncryptedJWT<SignedJWT> {
    pub fn new_signed(header: JweHeader, payload: SignedJWT, serialized_repr: String) -> Self {
        Self {
            header,
            payload,
            serialized_repr,
        }
    }

    pub fn signed_payload(&self) -> &SignedJWT {
        &self.payload
    }
}

impl EncryptedJWT<JwtPayload> {
    pub fn new(header: JweHeader, payload: JwtPayload, serialized_repr: String) -> Self {
        Self {
            header,
            payload,
            serialized_repr,
        }
    }
}

impl JWT for EncryptedJWT<JwtPayload> {
    type Header = JweHeader;

    fn header(&self) -> &Self::Header {
        &self.header
    }

    fn payload(&self) -> &JwtPayload {
        &self.payload
    }

    fn serialized(&self) -> &str {
        &self.serialized_repr
    }

    fn serialized_owned(self) -> String {
        self.serialized_repr
    }
}

impl JWT for EncryptedJWT<SignedJWT> {
    type Header = JweHeader;

    fn header(&self) -> &Self::Header {
        &self.header
    }

    fn payload(&self) -> &JwtPayload {
        &self.payload.payload
    }

    fn serialized(&self) -> &str {
        &self.serialized_repr
    }

    fn serialized_owned(self) -> String {
        self.serialized_repr
    }
}

impl<T> Serialize for EncryptedJWT<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.serialized_repr)
    }
}
impl Serialize for SignedJWT {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.serialized())
    }
}

impl<'de> Deserialize<'de> for SignedJWT {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct JWSVisitor;
        impl<'de> Visitor<'de> for JWSVisitor {
            type Value = SignedJWT;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("an signed jws string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                SignedJWT::decode_no_verify(v).map_err(|err| E::custom(err))
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

    use crate::jose::jwt2::SignedJWT;

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

        let jwt: SignedJWT = SignedJWT {
            header: jwt_header,
            payload: jwt_payload,
            serialized_repr: encoded_jwt.clone(),
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
        let jwt = SignedJWT::new(jwt_header, jwt_payload, &rsa_key).unwrap();

        jwt.verify(&rsa_key).expect("Error validating JWT");

        assert_eq!(expected_issuer, jwt.payload.issuer().unwrap());
        assert_eq!(expected_token_type, jwt.header.token_type().unwrap());
        assert_eq!(
            expected_token_id,
            Uuid::parse_str(jwt.payload.jwt_id().unwrap()).unwrap()
        );
    }
}
