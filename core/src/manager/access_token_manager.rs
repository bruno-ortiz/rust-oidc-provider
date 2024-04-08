use std::sync::Arc;

use anyhow::Context;
use uuid::Uuid;

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::models::access_token::AccessToken;
use crate::persistence::TransactionId;

pub struct AccessTokenManager {
    provider: Arc<OpenIDProviderConfiguration>,
}

impl AccessTokenManager {
    pub fn new(provider: Arc<OpenIDProviderConfiguration>) -> Self {
        Self { provider }
    }

    pub async fn find(&self, id: &str) -> Result<Option<AccessToken>, PersistenceError> {
        let id = Uuid::parse_str(id).context("Failed to parse UUID")?;
        self.provider.adapter().token().find(&id).await
    }

    pub async fn save(
        &self,
        access_token: AccessToken,
        txn: Option<TransactionId>,
    ) -> Result<AccessToken, PersistenceError> {
        self.provider
            .adapter()
            .token()
            .insert(access_token, txn)
            .await
    }
}
