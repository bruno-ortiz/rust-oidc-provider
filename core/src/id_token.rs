use indexmap::IndexMap;

use std::time::SystemTime;

use josekit::jwk::Jwk;
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;
use josekit::{Number, Value};
use oidc_types::hash::Hashable;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::error::OpenIdError;
use crate::hash::TokenHasher;
use crate::models::access_token::AccessToken;
use oidc_types::authorisation_code::AuthorisationCode;
use oidc_types::issuer::Issuer;
use oidc_types::jose::error::JWTError;
use oidc_types::jose::jwt::JWT;
use oidc_types::jose::JwsHeaderExt;
use oidc_types::nonce::Nonce;
use oidc_types::state::State;
use oidc_types::subject::Subject;

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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdToken(JWT);

impl IdToken {
    pub fn builder(signing_key: &Jwk) -> IdTokenBuilder {
        IdTokenBuilder::new(signing_key)
    }

    pub fn payload(&self) -> &JwtPayload {
        self.0.payload()
    }

    pub fn serialized(self) -> String {
        self.0.serialize_owned()
    }
}

#[derive(Debug)]
pub struct IdTokenBuilder<'a> {
    signing_key: &'a Jwk,
    issuer: Option<&'a Issuer>,
    sub: Option<&'a Subject>,
    audience: Vec<String>,
    expires_at: Option<OffsetDateTime>,
    issued_at: Option<OffsetDateTime>,
    auth_time: Option<OffsetDateTime>,
    nonce: Option<Nonce>,
    acr: Option<String>,
    amr: Option<String>,
    azp: Option<String>,
    s_hash: Option<String>,
    c_hash: Option<String>,
    at_hash: Option<String>,
}

impl<'a> IdTokenBuilder<'a> {
    fn new(signing_key: &'a Jwk) -> Self {
        IdTokenBuilder {
            signing_key,
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

    pub fn with_issuer(mut self, issuer: &'a Issuer) -> Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn with_sub(mut self, sub: &'a Subject) -> Self {
        self.sub = Some(sub);
        self
    }

    pub fn with_audience(mut self, aud: Vec<String>) -> Self {
        self.audience = aud;
        self
    }

    pub fn with_exp(mut self, exp: OffsetDateTime) -> Self {
        self.expires_at = Some(exp);
        self
    }

    pub fn with_iat(mut self, iat: OffsetDateTime) -> Self {
        self.issued_at = Some(iat);
        self
    }

    pub fn with_auth_time(mut self, auth_time: OffsetDateTime) -> Self {
        self.auth_time = Some(auth_time);
        self
    }

    pub fn with_nonce(mut self, nonce: Option<&Nonce>) -> Self {
        self.nonce = nonce.cloned();
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

    pub fn with_c_hash(mut self, code: Option<&AuthorisationCode>) -> Result<Self, OpenIdError> {
        if let Some(code) = code {
            let c_hash = Self::build_hash(self.signing_key, code)?;
            self.c_hash = Some(c_hash);
        }
        Ok(self)
    }

    pub fn with_s_hash(mut self, state: Option<&State>) -> Result<Self, OpenIdError> {
        if let Some(state) = state {
            let s_hash = Self::build_hash(self.signing_key, state)?;
            self.s_hash = Some(s_hash);
        }
        Ok(self)
    }

    pub fn with_at_hash(mut self, access_token: Option<&AccessToken>) -> Result<Self, OpenIdError> {
        if let Some(at) = access_token {
            let at_hash = Self::build_hash(self.signing_key, at)?;
            self.at_hash = Some(at_hash);
        }
        Ok(self)
    }

    pub fn build(mut self) -> Result<IdToken, IdTokenError> {
        let header = JwsHeader::from_key(self.signing_key);
        let mut payload = JwtPayload::new();
        if self.audience.is_empty() {
            return Err(IdTokenError::MissingRequiredClaim("audience".to_owned()));
        }
        payload.set_audience(self.audience);
        payload.set_issuer(self.issuer.required("issuer")?);
        payload.set_subject(self.sub.required("sub")?);
        payload.set_expires_at(&self.expires_at.required("expires_at")?.into());
        payload.set_issued_at(&self.issued_at.required("issued_at")?.into());

        payload.set_auth_time(self.auth_time);
        payload.set_nonce(self.nonce);
        payload.set_acr(self.acr);
        payload.set_amr(self.amr);
        payload.set_azp(self.azp);
        payload.set_s_hash(self.s_hash);
        payload.set_c_hash(self.c_hash);
        payload.set_at_hash(self.at_hash);
        let jwt = JWT::new(header, payload, self.signing_key)
            .map_err(|err| IdTokenError::EncodingErr { source: err })?;
        Ok(IdToken(jwt))
    }

    fn build_hash<H: Hashable>(signing_key: &Jwk, hashable: &H) -> Result<String, OpenIdError> {
        let hash = hashable
            .hash(signing_key)
            .map_err(|source| OpenIdError::server_error(source.into()))?;
        Ok(hash)
    }
}

trait JwtPayloadExt {
    fn set_auth_time(&mut self, value: Option<OffsetDateTime>);
    fn set_nonce(&mut self, value: Option<Nonce>);
    fn set_acr(&mut self, value: Option<String>);
    fn set_amr(&mut self, value: Option<String>);
    fn set_azp(&mut self, value: Option<String>);
    fn set_s_hash(&mut self, value: Option<String>);
    fn set_c_hash(&mut self, value: Option<String>);
    fn set_at_hash(&mut self, value: Option<String>);
}

impl JwtPayloadExt for JwtPayload {
    fn set_auth_time(&mut self, value: Option<OffsetDateTime>) {
        if let Some(time) = value {
            let time = SystemTime::from(time);
            let val = Number::from(
                time.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
            self.set_claim("auth_time", Some(Value::Number(val)))
                .expect("Cannot set auth_time on JWT");
        }
    }

    fn set_nonce(&mut self, value: Option<Nonce>) {
        if let Some(nonce) = value {
            self.set_claim("nonce", Some(Value::String(nonce.into())))
                .expect("Cannot set nonce on JWT");
        }
    }

    fn set_acr(&mut self, value: Option<String>) {
        if let Some(acr) = value {
            self.set_claim("acr", Some(Value::String(acr)))
                .expect("Cannot set acr on JWT");
        }
    }

    fn set_amr(&mut self, value: Option<String>) {
        if let Some(amr) = value {
            self.set_claim("amr", Some(Value::String(amr)))
                .expect("Cannot set amr on JWT");
        }
    }

    fn set_azp(&mut self, value: Option<String>) {
        if let Some(azp) = value {
            self.set_claim("azp", Some(Value::String(azp)))
                .expect("Cannot set azp on JWT");
        }
    }

    fn set_s_hash(&mut self, value: Option<String>) {
        if let Some(s_hash) = value {
            self.set_claim("s_hash", Some(Value::String(s_hash)))
                .expect("Cannot set s_hash on JWT");
        }
    }

    fn set_c_hash(&mut self, value: Option<String>) {
        if let Some(c_hash) = value {
            self.set_claim("c_hash", Some(Value::String(c_hash)))
                .expect("Cannot set c_hash on JWT");
        }
    }

    fn set_at_hash(&mut self, value: Option<String>) {
        if let Some(at_hash) = value {
            self.set_claim("at_hash", Some(Value::String(at_hash)))
                .expect("Cannot set at_hash on JWT");
        }
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
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("id_token".to_owned(), self.0.serialize_owned());
        map
    }
}
