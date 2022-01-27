use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;

use crate::adapter::{Adapter, PersistenceError};
use crate::authorisation_code::AuthorisationCode;

struct InMemoryAuthorisationCodeAdapter {
    storage: RwLock<HashMap<String, AuthorisationCode>>,
}

#[async_trait]
impl Adapter for InMemoryAuthorisationCodeAdapter {
    type Item = AuthorisationCode;

    async fn find<I: Into<String> + Send>(&self, id: I) -> Option<Self::Item> {
        let id = id.into();
        let storage = self.storage.read().unwrap();
        let item = storage.get(&id).cloned();
        item
    }

    async fn save(&self, item: Self::Item) -> Result<(), PersistenceError> {
        let mut storage = self.storage.write().unwrap();
        let id = item.code.clone();
        storage.insert(id, item);
        Ok(())
    }
}
