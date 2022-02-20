use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;
use uuid::Uuid;

use crate::adapter::{Adapter, PersistenceError};
use crate::services::interaction::Interaction;

pub struct InMemoryInteractionAdapter {
    storage: RwLock<HashMap<Uuid, Interaction>>,
}

impl InMemoryInteractionAdapter {
    pub fn new() -> Self {
        Self {
            storage: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Adapter for InMemoryInteractionAdapter {
    type Item = Interaction;
    type Id = Uuid;

    async fn find(&self, id: &Self::Id) -> Option<Self::Item> {
        let storage = self.storage.read().unwrap();
        let item = storage.get(id).cloned();
        item
    }

    async fn save(&self, item: Self::Item) -> Result<(), PersistenceError> {
        let mut storage = self.storage.write().unwrap();
        storage.insert(*item.id(), item);
        Ok(())
    }
}
