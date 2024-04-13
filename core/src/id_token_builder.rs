use std::borrow::Cow;
use std::collections::HashMap;
use std::time::SystemTime;

use josekit::jwk::Jwk;
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;
use josekit::{JoseError, Number, Value};
use serde::de::DeserializeOwned;
use thiserror::Error;
use time::OffsetDateTime;

use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::code::Code;
use oidc_types::hash::Hashable;
use oidc_types::issuer::Issuer;
use oidc_types::jose::error::JWTError;
use oidc_types::jose::jws::JwsHeaderExt;
use oidc_types::jose::jwt2::SignedJWT;
use oidc_types::nonce::Nonce;
use oidc_types::state::State;
use oidc_types::subject::Subject;

use crate::error::OpenIdError;
use crate::hash::TokenHasher;
use crate::id_token::IdToken;
use crate::models::access_token::AccessToken;

#[derive(Error, Debug)]
pub enum IdTokenError {
    #[error("Error encoding id_token")]
    EncodingErr {
        #[from]
        source: JWTError,
    },
    #[error("Required id_token claim {} not found", .0)]
    MissingRequiredClaim(String),
    #[error("Failed to set claim")]
    SetClaimFailure(#[source] JoseError),
    #[error("Error encrypting IDToken")]
    EncryptingErr(#[source] JWTError),
    #[error("Invalid client configuration: {}", .0)]
    InvalidClient(String),
}

#[derive(Debug)]
pub struct IdTokenBuilder<'a> {
    signing_key: &'a Jwk,
    issuer: Option<&'a Issuer>,
    sub: Option<&'a Subject>,
    audience: Vec<String>,
    expires_at: Option<OffsetDateTime>,
    issued_at: Option<OffsetDateTime>,
    nonce: Option<&'a Nonce>,
    azp: Option<String>,
    s_hash: Option<String>,
    c_hash: Option<String>,
    at_hash: Option<String>,
    auth_time: Option<OffsetDateTime>,
    custom_claims: HashMap<&'a str, Cow<'a, Value>>,
}

impl<'a> IdTokenBuilder<'a> {
    pub fn new(signing_key: &'a Jwk) -> Self {
        IdTokenBuilder {
            signing_key,
            issuer: None,
            sub: None,
            audience: Vec::new(),
            expires_at: None,
            issued_at: None,
            nonce: None,
            azp: None,
            s_hash: None,
            c_hash: None,
            at_hash: None,
            auth_time: None,
            custom_claims: HashMap::new(),
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

    pub fn with_nonce(mut self, nonce: Option<&'a Nonce>) -> Self {
        self.nonce = nonce;
        self
    }
    pub fn with_azp(mut self, azp: &str) -> Self {
        self.azp = Some(azp.to_owned());
        self
    }

    pub fn with_claim<T: Into<Value>>(mut self, key: &'a str, value: T) -> Self {
        self.custom_claims.insert(key, Cow::Owned(value.into()));
        self
    }

    pub fn with_auth_time(mut self, auth_time: OffsetDateTime) -> Self {
        self.auth_time = Some(auth_time);
        self
    }

    pub fn with_custom_claims(mut self, claims: HashMap<&'a str, &'a Value>) -> Self {
        self.custom_claims
            .extend(claims.iter().map(|(&k, &v)| (k, Cow::Borrowed(v))));
        self
    }

    pub fn with_c_hash(mut self, code: Option<&Code>) -> Result<Self, OpenIdError> {
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

    pub fn build(mut self) -> Result<IdToken<SignedJWT>, IdTokenError> {
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

        payload.set_nonce(self.nonce.cloned());
        payload.set_azp(self.azp);
        payload.set_s_hash(self.s_hash);
        payload.set_c_hash(self.c_hash);
        payload.set_at_hash(self.at_hash);

        for (claim, value) in self.custom_claims {
            payload
                .set_claim(claim, Some(value.into_owned()))
                .map_err(IdTokenError::SetClaimFailure)?;
        }

        let jwt = SignedJWT::new(header, payload, self.signing_key)
            .map_err(|err| IdTokenError::EncodingErr { source: err })?;
        Ok(IdToken::new(jwt))
    }

    fn build_hash<H: Hashable>(signing_key: &Jwk, hashable: &H) -> Result<String, OpenIdError> {
        let hash = hashable
            .hash(signing_key)
            .map_err(OpenIdError::server_error)?;
        Ok(hash)
    }
}

pub trait JwtPayloadExt {
    fn set_auth_time(&mut self, value: Option<OffsetDateTime>);
    fn set_nonce(&mut self, value: Option<Nonce>);
    fn set_acr(&mut self, value: Option<&Acr>);
    fn set_amr(&mut self, value: Option<&Amr>);
    fn set_azp(&mut self, value: Option<String>);
    fn set_s_hash(&mut self, value: Option<String>);
    fn set_c_hash(&mut self, value: Option<String>);
    fn set_at_hash(&mut self, value: Option<String>);
    fn convert<T: DeserializeOwned>(&self) -> serde_json::Result<T>;
}

impl JwtPayloadExt for JwtPayload {
    fn set_auth_time(&mut self, value: Option<OffsetDateTime>) {
        if let Some(time) = value {
            let time = SystemTime::from(time);
            let val = Number::from(
                time.duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Time is before epoch")
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

    fn set_acr(&mut self, value: Option<&Acr>) {
        if let Some(acr) = value {
            self.set_claim("acr", Some(Value::String(acr.to_string())))
                .expect("Cannot set acr on JWT");
        }
    }

    fn set_amr(&mut self, value: Option<&Amr>) {
        if let Some(amr) = value {
            self.set_claim("amr", Some(Value::String(amr.to_string())))
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

    fn convert<T: DeserializeOwned>(&self) -> serde_json::Result<T> {
        let value = serde_json::to_value(self.as_ref())?;
        serde_json::from_value::<T>(value)
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
