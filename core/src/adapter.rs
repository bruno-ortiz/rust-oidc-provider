use std::fmt::Debug;

use async_trait::async_trait;
use thiserror::Error;

pub mod generic_adapter;

#[derive(Error, Debug)]
pub enum PersistenceError {}

#[async_trait]
pub trait Adapter {
    type Item: Send + Sync;
    type Id: Sized;

    async fn find(&self, id: &Self::Id) -> Option<Self::Item>;

    async fn save(&self, item: Self::Item) -> Result<Self::Item, PersistenceError>;
}
