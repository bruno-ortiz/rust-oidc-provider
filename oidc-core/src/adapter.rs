use std::fmt::{Debug, Formatter};

use async_trait::async_trait;
use thiserror::Error;

pub mod client_adapter;
pub mod code_adapter;
pub mod interaction_adapter;
pub mod user_adapter;

#[derive(Error, Debug)]
pub enum PersistenceError {}

#[async_trait]
pub trait Adapter {
    type Item;
    type Id: Sized;

    async fn find(&self, id: &Self::Id) -> Option<Self::Item>;

    async fn save(&self, item: Self::Item) -> Result<(), PersistenceError>;
}
