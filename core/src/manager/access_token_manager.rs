use std::sync::Arc;

use uuid::Uuid;

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::models::access_token::AccessToken;

pub struct AccessTokenManager {
    provider: Arc<OpenIDProviderConfiguration>,
}

impl AccessTokenManager {
    pub fn new(provider: Arc<OpenIDProviderConfiguration>) -> Self {
        Self { provider }
    }

    pub async fn find(&self, id: &str) -> Result<Option<AccessToken>, PersistenceError> {
        let id = Uuid::parse_str(id).map_err(|err| PersistenceError::Internal(err.into()))?;
        self.provider.adapter().token().find(&id).await
    }

    pub async fn save(&self, access_token: AccessToken) -> Result<AccessToken, PersistenceError> {
        self.provider
            .adapter()
            .token()
            .insert(access_token, None)
            .await
    }
}