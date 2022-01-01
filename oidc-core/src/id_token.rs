use std::collections::HashMap;
use std::time::SystemTime;

use chrono::{DateTime, TimeZone};
use josekit::jwk::Jwk;
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;
use josekit::{Number, Value};
use thiserror::Error;

use oidc_types::issuer::Issuer;
use oidc_types::jose::error::JWTError;
use oidc_types::jose::jwt::JWT;

use crate::response_type::UrlEncodable;

#[derive(Error, Debug)]
pub enum IdTokenError {
    #[error("Error encoding id_token")]
    EncodingErr {
        #[from]
        source: JWTError,
    },
    #[error("Required id_token claim {} not found", .0)]
    MissingRequiredClaim(String),
}

#[derive(Debug)]
pub struct IdToken(JWT);

impl IdToken {
    pub fn builder<Tz: TimeZone>() -> IdTokenBuilder<Tz> {
        IdTokenBuilder::new()
    }
}

#[derive(Debug)]
pub struct IdTokenBuilder<Tz: TimeZone> {
    issuer: Option<Issuer>,
    sub: Option<String>,
    audience: Vec<String>,
    expires_at: Option<DateTime<Tz>>,
    issued_at: Option<DateTime<Tz>>,
    auth_time: Option<DateTime<Tz>>,
    nonce: Option<String>,
    acr: Option<String>,
    amr: Option<String>,
    azp: Option<String>,
    s_hash: Option<String>,
    c_hash: Option<String>,
    at_hash: Option<String>,
}

impl<Tz: TimeZone> IdTokenBuilder<Tz> {
    fn new() -> Self {
        IdTokenBuilder {
            issuer: None,
            sub: None,
            audience: Vec::new(),
            expires_at: None,
            issued_at: None,
            auth_time: None,
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            s_hash: None,
            c_hash: None,
            at_hash: None,
        }
    }

    pub fn with_issuer(mut self, issuer: Issuer) -> Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn with_sub(mut self, sub: &str) -> Self {
        self.sub = Some(sub.to_owned());
        self
    }

    pub fn with_audience(mut self, aud: Vec<String>) -> Self {
        self.audience = aud;
        self
    }

    pub fn with_exp(mut self, exp: DateTime<Tz>) -> Self {
        self.expires_at = Some(exp);
        self
    }

    pub fn with_iat(mut self, iat: DateTime<Tz>) -> Self {
        self.issued_at = Some(iat);
        self
    }

    pub fn with_auth_time(mut self, auth_time: DateTime<Tz>) -> Self {
        self.auth_time = Some(auth_time);
        self
    }

    pub fn with_nonce(mut self, nonce: &str) -> Self {
        self.nonce = Some(nonce.to_owned());
        self
    }
    pub fn with_acr(mut self, acr: &str) -> Self {
        self.acr = Some(acr.to_owned());
        self
    }
    pub fn with_amr(mut self, amr: &str) -> Self {
        self.amr = Some(amr.to_owned());
        self
    }
    pub fn with_azp(mut self, azp: &str) -> Self {
        self.azp = Some(azp.to_owned());
        self
    }

    pub fn with_c_hash(mut self, c_hash: String) -> Self {
        self.c_hash = Some(c_hash);
        self
    }

    pub fn with_s_hash(mut self, s_hash: String) -> Self {
        self.s_hash = Some(s_hash);
        self
    }

    pub fn with_at_hash(mut self, at_hash: String) -> Self {
        self.at_hash = Some(at_hash);
        self
    }

    pub fn build(mut self, key: &Jwk) -> Result<IdToken, IdTokenError> {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_algorithm(
            key.algorithm()
                .expect("Expected alg parameter in signing key"),
        );
        let mut payload = JwtPayload::new();
        if self.audience.is_empty() {
            return Err(IdTokenError::MissingRequiredClaim("audience".to_owned()));
        }
        payload.set_audience(self.audience);
        payload.set_issuer(self.issuer.required("issuer")?);
        payload.set_subject(self.sub.required("sub")?);
        payload.set_expires_at(&self.expires_at.required("expires_at")?.into());
        payload.set_issued_at(&self.issued_at.required("issued_at")?.into());
        payload.set_auth_time(&self.auth_time.required("auth_time")?.into());
        payload.set_nonce(self.nonce.required("nonce")?);
        payload.set_acr(self.acr.required("acr")?);
        payload.set_amr(self.amr.required("amr")?);
        payload.set_azp(self.acr.required("azp")?);
        let jwt = JWT::new(header, payload, key)
            .map_err(|err| IdTokenError::EncodingErr { source: err })?;
        Ok(IdToken(jwt))
    }
}

trait JwtPayloadExt {
    fn set_auth_time(&mut self, value: &SystemTime);
    fn set_nonce(&mut self, value: impl Into<String>);
    fn set_acr(&mut self, value: impl Into<String>);
    fn set_amr(&mut self, value: impl Into<String>);
    fn set_azp(&mut self, value: impl Into<String>);
}

impl JwtPayloadExt for JwtPayload {
    fn set_auth_time(&mut self, value: &SystemTime) {
        let val = Number::from(
            value
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        self.set_claim("auth_time", Some(Value::Number(val)));
    }

    fn set_nonce(&mut self, value: impl Into<String>) {
        self.set_claim("nonce", Some(Value::String(value.into())));
    }

    fn set_acr(&mut self, value: impl Into<String>) {
        self.set_claim("acr", Some(Value::String(value.into())));
    }

    fn set_amr(&mut self, value: impl Into<String>) {
        self.set_claim("amr", Some(Value::String(value.into())));
    }

    fn set_azp(&mut self, value: impl Into<String>) {
        self.set_claim("azp", Some(Value::String(value.into())));
    }
}

trait OptionRequiredExt<T> {
    fn required(&mut self, param: &str) -> Result<T, IdTokenError>;
}

impl<T> OptionRequiredExt<T> for Option<T> {
    fn required(&mut self, param: &str) -> Result<T, IdTokenError> {
        if let Some(value) = self.take() {
            Ok(value)
        } else {
            Err(IdTokenError::MissingRequiredClaim(param.to_owned()))
        }
    }
}

impl UrlEncodable for IdToken {
    fn params(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("id_token".to_owned(), self.0.serialize().to_owned());
        map
    }
}
