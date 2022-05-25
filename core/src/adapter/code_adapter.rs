use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;

use crate::adapter::{Adapter, PersistenceError};
use crate::authorisation_code::AuthorisationCode;

pub struct InMemoryAuthorisationCodeAdapter {
    storage: RwLock<HashMap<String, AuthorisationCode>>,
}

impl InMemoryAuthorisationCodeAdapter {
    pub fn new() -> Self {
        Self {
            storage: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Adapter for InMemoryAuthorisationCodeAdapter {
    type Item = AuthorisationCode;
    type Id = String;

    async fn find(&self, id: &Self::Id) -> Option<Self::Item> {
        let storage = self.storage.read().unwrap();
        let item = storage.get(id).cloned();
        item
    }

    async fn save(&self, item: Self::Item) -> Result<Self::Item, PersistenceError> {
        let mut storage = self.storage.write().unwrap();
        let id = item.code.clone();
        storage.insert(id, item.clone());
        Ok(item)
    }
}
