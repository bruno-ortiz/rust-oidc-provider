use indexmap::IndexMap;
use serde::Serialize;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use oidc_types::hash::Hashable;
use oidc_types::identifiable::Identifiable;
use oidc_types::scopes::Scopes;
use oidc_types::url_encodable::UrlEncodable;

use crate::adapter::PersistenceError;
use crate::configuration::clock::{Clock, ClockProvider};
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::grant::{Grant, GrantID};

pub struct ActiveAccessToken {
    inner: AccessToken,
    grant: Grant,
}

impl ActiveAccessToken {
    pub fn new(at: AccessToken, grant: Grant) -> Self {
        Self { inner: at, grant }
    }

    pub fn grant(&self) -> &Grant {
        &self.grant
    }
    pub fn scopes(&self) -> Option<&Scopes> {
        self.inner.scopes.as_ref()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AccessToken {
    pub grant_id: GrantID,
    pub token: Uuid,
    pub t_type: String,
    pub expires_in: Duration,
    pub created: OffsetDateTime,
    pub scopes: Option<Scopes>,
}

impl AccessToken {
    pub const BEARER_TYPE: &'static str = "Bearer";

    pub fn new<TT: Into<String>>(
        clock: &ClockProvider,
        token_type: TT,
        expires_in: Duration,
        scopes: Option<Scopes>,
        grant_id: GrantID,
    ) -> Self {
        Self::new_with_value(
            Uuid::new_v4(),
            token_type,
            clock.now(),
            expires_in,
            scopes,
            grant_id,
        )
    }

    pub fn new_with_value<TT: Into<String>>(
        token_value: Uuid,
        token_type: TT,
        created: OffsetDateTime,
        expires_in: Duration,
        scopes: Option<Scopes>,
        grant_id: GrantID,
    ) -> Self {
        Self {
            token: token_value,
            t_type: token_type.into(),
            created,
            expires_in,
            scopes,
            grant_id,
        }
    }

    pub fn bearer(
        clock: &ClockProvider,
        grant_id: GrantID,
        expires_in: Duration,
        scopes: Option<Scopes>,
    ) -> Self {
        Self::new(
            clock,
            AccessToken::BEARER_TYPE,
            expires_in,
            scopes,
            grant_id,
        )
    }

    pub async fn find(
        provider: &OpenIDProviderConfiguration,
        id: &str,
    ) -> Result<Option<AccessToken>, PersistenceError> {
        let id = Uuid::parse_str(id).map_err(|err| PersistenceError::Internal(err.into()))?; //todo: revisit this code later, return err?
        provider.adapter().token().find(&id).await
    }

    pub async fn save(
        self,
        provider: &OpenIDProviderConfiguration,
    ) -> Result<AccessToken, PersistenceError> {
        provider.adapter().token().insert(self, None).await
    }
}

impl Identifiable<Uuid> for AccessToken {
    fn id(&self) -> &Uuid {
        &self.token
    }
}

impl UrlEncodable for AccessToken {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("access_token".to_owned(), self.token.to_string());
        map.insert("token_type".to_owned(), self.t_type);
        map.insert(
            "expires_in".to_owned(),
            self.expires_in.whole_seconds().to_string(),
        );
        map
    }
}

impl Hashable for AccessToken {
    fn identifier(&self) -> String {
        self.token.to_string()
    }
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Token expired")]
    Expired,
    #[error("Invalid grant")]
    InvalidGrant,
    #[error(transparent)]
    PersistenceError(#[from] PersistenceError),
}

impl From<TokenError> for OpenIdError {
    fn from(err: TokenError) -> Self {
        match err {
            TokenError::Expired => OpenIdError::invalid_grant(err.to_string()),
            TokenError::InvalidGrant => OpenIdError::invalid_grant(err.to_string()),
            TokenError::PersistenceError(e) => OpenIdError::server_error(e),
        }
    }
}
