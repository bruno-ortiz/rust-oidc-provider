use std::hash::{Hash, Hasher};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tracing::error;
use uuid::Uuid;

use crate::adapter::PersistenceError;

#[async_trait]
pub trait TransactionManager {
    async fn begin_txn(&self) -> Result<TransactionId, PersistenceError>;
    async fn commit(&self, id: TransactionId) -> Result<(), PersistenceError>;
    async fn rollback(&self, id: TransactionId) -> Result<(), PersistenceError>;
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct TransactionId(Arc<TransactionIdInner>);

impl TransactionId {
    pub fn new(id: Uuid, rollback_channel: Option<Sender<Uuid>>) -> Self {
        Self(Arc::new(TransactionIdInner(id, rollback_channel)))
    }

    pub fn id(&self) -> Uuid {
        self.0 .0
    }

    pub fn clone_some(&self) -> Option<Self> {
        Some(self.clone())
    }
}

#[derive(Debug)]
struct TransactionIdInner(Uuid, Option<Sender<Uuid>>);

impl Drop for TransactionIdInner {
    fn drop(&mut self) {
        if let Some(rollback_channel) = self.1.clone() {
            let txn_id = self.0;
            tokio::task::spawn(async move {
                if let Err(err) = rollback_channel.send(txn_id).await {
                    error!(
                        "Error trying to rollback transaction with id: {}, error: {}.",
                        txn_id, err
                    )
                }
            });
        }
    }
}

impl Hash for TransactionIdInner {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl PartialEq for TransactionIdInner {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for TransactionIdInner {}

#[derive(Default)]
pub struct NoOpTransactionManager;

#[async_trait]
impl TransactionManager for NoOpTransactionManager {
    async fn begin_txn(&self) -> Result<TransactionId, PersistenceError> {
        Ok(TransactionId::new(Uuid::new_v4(), None))
    }

    async fn commit(&self, _id: TransactionId) -> Result<(), PersistenceError> {
        Ok(())
    }

    async fn rollback(&self, _id: TransactionId) -> Result<(), PersistenceError> {
        Ok(())
    }
}
