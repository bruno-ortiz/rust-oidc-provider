use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;

use oidc_types::client::{ClientID, ClientInformation};

use crate::adapter::{Adapter, PersistenceError};

pub struct InMemoryClientAdapter {
    storage: RwLock<HashMap<ClientID, ClientInformation>>,
}

impl InMemoryClientAdapter {
    pub fn new() -> Self {
        Self {
            storage: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Adapter for InMemoryClientAdapter {
    type Item = ClientInformation;

    async fn find(&self, id: &str) -> Option<Self::Item> {
        let id = ClientID::new(id.into());
        let storage = self.storage.read().unwrap();
        let item = storage.get(&id).cloned();
        item
    }

    async fn save(&self, item: Self::Item) -> Result<(), PersistenceError> {
        let mut storage = self.storage.write().unwrap();
        let id = item.id.clone();
        storage.insert(id, item);
        Ok(())
    }
}
