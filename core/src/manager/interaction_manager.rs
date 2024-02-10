use std::sync::Arc;

use uuid::Uuid;

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::persistence::TransactionId;
use crate::services::types::Interaction;

pub struct InteractionManager {
    provider: Arc<OpenIDProviderConfiguration>,
}

impl InteractionManager {
    pub fn new(provider: Arc<OpenIDProviderConfiguration>) -> Self {
        Self { provider }
    }

    pub async fn find(&self, id: Uuid) -> Result<Option<Interaction>, PersistenceError> {
        self.provider.adapter().interaction().find(&id).await
    }

    pub async fn save(
        &self,
        interaction: Interaction,
        txn: Option<TransactionId>,
    ) -> Result<Interaction, PersistenceError> {
        self.provider
            .adapter()
            .interaction()
            .insert(interaction, txn)
            .await
    }

    pub async fn update(
        &self,
        interaction: Interaction,
        txn: Option<TransactionId>,
    ) -> Result<Interaction, PersistenceError> {
        self.provider
            .adapter()
            .interaction()
            .update(interaction, txn)
            .await
    }
}
