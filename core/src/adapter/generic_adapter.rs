use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use dashmap::DashMap;

use oidc_types::identifiable::Identifiable;

use crate::adapter::{Adapter, PersistenceError};
use crate::persistence::TransactionId;

#[derive(Debug, Clone)]
pub struct InMemoryGenericAdapter<ID, IT>
where
    ID: Eq + Hash + Send + Sync + Clone + Debug,
{
    storage: Arc<DashMap<ID, IT>>,
}

impl<ID, IT> InMemoryGenericAdapter<ID, IT>
where
    ID: Eq + Hash + Send + Sync + Clone + Debug,
{
    pub fn new() -> Self {
        Self {
            storage: Arc::new(DashMap::new()),
        }
    }
}

#[async_trait]
impl<ID, IT> Adapter for InMemoryGenericAdapter<ID, IT>
where
    ID: Eq + Hash + Send + Sync + Clone + Debug,
    IT: Identifiable<ID> + Send + Sync + Clone + Debug,
{
    type Id = ID;
    type Item = IT;

    async fn find(&self, id: &Self::Id) -> Result<Option<Self::Item>, PersistenceError> {
        let item = self.storage.get(id).map(|item| item.value().clone());
        Ok(item)
    }

    async fn insert(
        &self,
        item: Self::Item,
        _active_txn: Option<TransactionId>,
    ) -> Result<Self::Item, PersistenceError> {
        let id = item.id();
        if self.storage.contains_key(id) {
            return Err(PersistenceError::DB(anyhow!(
                "Storage already contains item with id: {:?}",
                id
            )));
        }
        self.storage.insert(id.clone(), item.clone());
        Ok(item)
    }

    async fn update(
        &self,
        item: Self::Item,
        _active_txn: Option<TransactionId>,
    ) -> Result<Self::Item, PersistenceError> {
        let id = item.id();
        if !self.storage.contains_key(id) {
            return Err(PersistenceError::DB(anyhow!(
                "Storage does not contain item with id: {:?}",
                id
            )));
        }
        self.storage.insert(id.clone(), item.clone());
        Ok(item)
    }
}
