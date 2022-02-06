use std::fmt::{Debug, Formatter};

use async_trait::async_trait;
use thiserror::Error;

pub mod client_adapter;
pub mod code_adapter;

#[derive(Error, Debug)]
pub enum PersistenceError {}

#[async_trait]
pub trait Adapter {
    type Item;

    async fn find(&self, id: &str) -> Option<Self::Item>;

    async fn save(&self, item: Self::Item) -> Result<(), PersistenceError>;
}

impl<T: Debug> Debug for dyn Adapter<Item = T> + Send + Sync {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Generic Adapter")
    }
}
