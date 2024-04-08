use oidc_types::scopes::Scopes;
use time::{Duration, OffsetDateTime};

use super::{
    access_token::AccessToken,
    grant::{Grant, GrantID},
    refresh_token::RefreshToken,
};

pub const ACCESS_TOKEN: &str = "access_token";
pub const REFRESH_TOKEN: &str = "refresh_token";

pub trait Token {
    fn created(&self) -> OffsetDateTime;
    fn expires_in(&self) -> Duration;
    fn grant_id(&self) -> GrantID;
    fn scopes(&self) -> Option<&Scopes>;
    fn token_type(&self) -> Option<&str>;
}

#[derive(Debug)]
pub struct ActiveToken<T> {
    token: T,
    grant: Grant,
}

impl<T> ActiveToken<T>
where
    T: Token,
{
    pub fn new(token: T, grant: Grant) -> Self {
        Self { token, grant }
    }

    pub fn grant(&self) -> &Grant {
        &self.grant
    }
    pub fn token(&self) -> &T {
        &self.token
    }
}

impl<T> Token for ActiveToken<T>
where
    T: Token,
{
    fn created(&self) -> OffsetDateTime {
        self.token.created()
    }
    fn expires_in(&self) -> Duration {
        self.token.expires_in()
    }
    fn grant_id(&self) -> GrantID {
        self.token.grant_id()
    }
    fn scopes(&self) -> Option<&Scopes> {
        self.token.scopes()
    }

    fn token_type(&self) -> Option<&str> {
        self.token.token_type()
    }
}

#[derive(Debug)]
pub enum TokenByType {
    Access(AccessToken),
    Refresh(RefreshToken),
}

impl Token for TokenByType {
    fn created(&self) -> OffsetDateTime {
        match self {
            TokenByType::Access(token) => token.created(),
            TokenByType::Refresh(token) => token.created(),
        }
    }
    fn expires_in(&self) -> Duration {
        match self {
            TokenByType::Access(token) => token.expires_in(),
            TokenByType::Refresh(token) => token.expires_in(),
        }
    }
    fn grant_id(&self) -> GrantID {
        match self {
            TokenByType::Access(token) => token.grant_id(),
            TokenByType::Refresh(token) => token.grant_id(),
        }
    }
    fn scopes(&self) -> Option<&Scopes> {
        match self {
            TokenByType::Access(token) => token.scopes(),
            TokenByType::Refresh(token) => token.scopes(),
        }
    }
    fn token_type(&self) -> Option<&str> {
        match self {
            TokenByType::Access(token) => token.token_type(),
            TokenByType::Refresh(_) => None,
        }
    }
}
