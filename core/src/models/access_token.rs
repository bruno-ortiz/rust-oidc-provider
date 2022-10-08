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
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::grant::GrantID;

pub struct ActiveAccessToken(AccessToken);

impl ActiveAccessToken {
    pub fn grant_id(&self) -> GrantID {
        self.0.grant_id
    }
    pub fn scopes(&self) -> Option<&Scopes> {
        self.0.scopes.as_ref()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AccessToken {
    grant_id: GrantID,
    pub token: String,
    pub t_type: String,
    pub expires_in: Duration,
    pub created: OffsetDateTime,
    pub scopes: Option<Scopes>,
}

impl AccessToken {
    pub const BEARER_TYPE: &'static str = "Bearer";

    pub fn new<TT: Into<String>>(
        token_type: TT,
        expires_in: Duration,
        scopes: Option<Scopes>,
        grant_id: GrantID,
    ) -> Self {
        let clock = OpenIDProviderConfiguration::clock();
        Self {
            token: Uuid::new_v4().to_string(),
            t_type: token_type.into(),
            created: clock.now(),
            expires_in,
            scopes,
            grant_id,
        }
    }

    pub fn bearer(grant_id: GrantID, expires_in: Duration, scopes: Option<Scopes>) -> Self {
        Self::new(AccessToken::BEARER_TYPE, expires_in, scopes, grant_id)
    }

    pub fn into_active(self) -> Result<ActiveAccessToken, TokenError> {
        let clock = OpenIDProviderConfiguration::clock();
        let now = clock.now();
        if now <= (self.created + self.expires_in) {
            Ok(ActiveAccessToken(self))
        } else {
            Err(TokenError::Expired)
        }
    }

    pub async fn find(id: &str) -> Option<AccessToken> {
        let configuration = OpenIDProviderConfiguration::instance();
        configuration.adapters().token().find(&id.to_string()).await //todo: revisit this code later
    }

    pub async fn save(self) -> Result<AccessToken, PersistenceError> {
        let configuration = OpenIDProviderConfiguration::instance();
        configuration.adapters().token().save(self).await
    }
}

impl Identifiable<String> for AccessToken {
    fn id(&self) -> String {
        self.token.clone()
    }
}

impl UrlEncodable for AccessToken {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("access_token".to_owned(), self.token);
        map.insert("token_type".to_owned(), self.t_type);
        map.insert(
            "expires_in".to_owned(),
            self.expires_in.whole_seconds().to_string(),
        );
        map
    }
}

impl Hashable for AccessToken {
    fn identifier(&self) -> &str {
        &self.token
    }
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Token expired")]
    Expired,
}

impl From<TokenError> for OpenIdError {
    fn from(err: TokenError) -> Self {
        match err {
            TokenError::Expired => OpenIdError::invalid_grant(err.to_string()),
        }
    }
}
