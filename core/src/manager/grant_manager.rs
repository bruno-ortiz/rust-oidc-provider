use std::sync::Arc;

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::grant::{Grant, GrantID};
use crate::models::Status;
use crate::persistence::TransactionId;

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

    pub async fn save(
        &self,
        grant: Grant,
        txn: Option<TransactionId>,
    ) -> Result<Grant, PersistenceError> {
        self.provider.adapter().grant().insert(grant, txn).await
    }

    pub async fn update(
        &self,
        grant: Grant,
        txn: Option<TransactionId>,
    ) -> Result<Grant, PersistenceError> {
        self.provider.adapter().grant().update(grant, txn).await
    }

    pub async fn consume(
        &self,
        mut grant: Grant,
        txn: Option<TransactionId>,
    ) -> Result<Grant, OpenIdError> {
        grant.set_status(Status::Consumed);
        self.update(grant, txn)
            .await
            .map_err(OpenIdError::server_error)
    }
}
