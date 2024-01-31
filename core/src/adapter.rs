use crate::persistence::TransactionId;
use async_trait::async_trait;
use base64::DecodeError;
use thiserror::Error;

pub(crate) mod generic_adapter;

#[derive(Error, Debug)]
pub enum PersistenceError {
    #[error("Internal error: {}", .0)]
    Internal(#[from] anyhow::Error),
    #[error("Error converting column of type json, {}", .0)]
    Json(#[from] serde_json::Error),
    #[error("Error converting column of type url, {}", .0)]
    Url(#[from] url::ParseError),
    #[error("Failed to convert byte vec to UUID: {:?}",.0)]
    UUID(#[from] uuid::Error),
    #[error("Failed to decode b64 column: {:?}",.0)]
    B64(#[from] DecodeError),
    #[error("Error executing statement: {}",.0)]
    DB(anyhow::Error),
}

#[async_trait]
pub trait Adapter {
    type Id;
    type Item;
    async fn find(&self, id: &Self::Id) -> Result<Option<Self::Item>, PersistenceError>;

    async fn insert(
        &self,
        item: Self::Item,
        active_txn: Option<TransactionId>,
    ) -> Result<Self::Item, PersistenceError>;

    async fn update(
        &self,
        item: Self::Item,
        active_txn: Option<TransactionId>,
    ) -> Result<Self::Item, PersistenceError>;
}
