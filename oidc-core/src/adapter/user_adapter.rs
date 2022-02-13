use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;

use crate::adapter::{Adapter, PersistenceError};
use crate::session::AuthenticatedUser;

pub struct InMemoryUserAdapter {
    storage: RwLock<HashMap<String, AuthenticatedUser>>,
}

impl InMemoryUserAdapter {
    pub fn new() -> Self {
        Self {
            storage: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Adapter for InMemoryUserAdapter {
    type Item = AuthenticatedUser;
    type Id = String;

    async fn find(&self, id: &Self::Id) -> Option<Self::Item> {
        let storage = self.storage.read().unwrap();
        let item = storage.get(id).cloned();
        item
    }

    async fn save(&self, item: Self::Item) -> Result<(), PersistenceError> {
        let mut storage = self.storage.write().unwrap();
        let id = item.session();
        storage.insert(id.to_string(), item);
        Ok(())
    }
}
