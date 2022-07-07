use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::sync::RwLock;

use async_trait::async_trait;
use oidc_types::identifiable::Identifiable;

use crate::adapter::{Adapter, PersistenceError};
use crate::authorisation_code::AuthorisationCode;

pub struct InMemoryGenericAdapter<ID, IT> {
    storage: RwLock<HashMap<ID, IT>>,
}

impl<ID, IT> InMemoryGenericAdapter<ID, IT> {
    pub fn new() -> Self {
        Self {
            storage: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl<ID, IT> Adapter for InMemoryGenericAdapter<ID, IT>
where
    ID: Eq + Hash + Send + Sync,
    IT: Identifiable<ID> + Send + Sync + Clone,
{
    type Item = IT;
    type Id = ID;

    async fn find(&self, id: &Self::Id) -> Option<Self::Item> {
        let storage = self.storage.read().unwrap();
        let item = storage.get(id).cloned();
        item
    }

    async fn save(&self, item: Self::Item) -> Result<Self::Item, PersistenceError> {
        let mut storage = self.storage.write().unwrap();
        let id = item.id();
        storage.insert(id, item.clone());
        Ok(item)
    }
}
