use std::sync::Arc;

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::grant::{Grant, GrantID};
use crate::models::Status;

pub struct GrantManager {
    provider: Arc<OpenIDProviderConfiguration>,
}

impl GrantManager {
    pub fn new(provider: Arc<OpenIDProviderConfiguration>) -> Self {
        Self { provider }
    }

    pub async fn find(&self, id: GrantID) -> Result<Option<Grant>, PersistenceError> {
        Ok(self
            .provider
            .adapter()
            .grant()
            .find(&id)
            .await?
            .filter(|it| it.status() != Status::Consumed))
    }

    pub async fn save(&self, grant: Grant) -> Result<Grant, PersistenceError> {
        self.provider.adapter().grant().insert(grant, None).await
    }

    pub async fn update(&self, grant: Grant) -> Result<Grant, PersistenceError> {
        self.provider.adapter().grant().update(grant, None).await
    }

    pub async fn consume(&self, mut grant: Grant) -> Result<Grant, OpenIdError> {
        grant.set_status(Status::Consumed);
        self.update(grant).await.map_err(OpenIdError::server_error)
    }
}
