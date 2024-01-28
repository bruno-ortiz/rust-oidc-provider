use anyhow::anyhow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use oidc_types::identifiable::Identifiable;

use crate::adapter::{Adapter, PersistenceError};

#[derive(Debug, Clone)]
pub struct InMemoryGenericAdapter<ID, IT> {
    storage: Arc<RwLock<HashMap<ID, IT>>>,
}

impl<ID, IT> InMemoryGenericAdapter<ID, IT> {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
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
        let storage = self
            .storage
            .read()
            .expect("Error getting read lock in Generic Adapter");
        let item = storage.get(id).cloned();
        Ok(item)
    }

    async fn insert(&self, item: Self::Item) -> Result<Self::Item, PersistenceError> {
        let id = item.id();
        let storage = self
            .storage
            .read()
            .expect("Error getting read lock in Generic Adapter");
        if storage.contains_key(id) {
            return Err(PersistenceError::DB(anyhow!(
                "Storage already contains item with id: {:?}",
                id
            )));
        }
        drop(storage);
        let mut storage = self
            .storage
            .write()
            .expect("Error getting write lock in Generic Adapter");

        storage.insert(id.clone(), item.clone());
        Ok(item)
    }

    async fn update(&self, item: Self::Item) -> Result<Self::Item, PersistenceError> {
        let mut storage = self
            .storage
            .write()
            .expect("Error getting write lock in Generic Adapter");
        let id = item.id();
        storage.insert(id.clone(), item.clone());
        Ok(item)
    }
}
