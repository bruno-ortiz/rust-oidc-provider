use async_trait::async_trait;
use thiserror::Error;

mod client_adapter;
mod code_adapter;

#[derive(Error, Debug)]
enum PersistenceError {}

#[async_trait]
trait Adapter {
    type Item;

    async fn find<I: Into<String> + Send>(&self, id: I) -> Option<Self::Item>;

    async fn save(&self, item: Self::Item) -> Result<(), PersistenceError>;
}
