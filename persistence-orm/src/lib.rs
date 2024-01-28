use std::error::Error;
use std::ops::Deref;
use std::sync::Arc;

use anyhow::anyhow;
pub use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sea_orm::{DatabaseTransaction, TransactionTrait};

use oidc_core::persistence::{Transaction, TransactionManager, TransactionWrapper};
use oidc_migration::async_trait::async_trait;

pub mod adapter;
mod entities;
mod repository;
mod utils;

struct TxnWrapper(DatabaseTransaction);

#[async_trait]
impl Transaction for TxnWrapper {
    async fn commit(mut self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        let txn = Arc::into_inner(self).ok_or(anyhow!(
            "Error trying to commit transaction, are you still holding a ref somewhere?"
        ))?;
        txn.0.commit().await?;
        Ok(())
    }

    async fn rollback(mut self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        let txn = Arc::into_inner(self).ok_or(anyhow!(
            "Error trying to rollback transaction, are you still holding a ref somewhere?"
        ))?;
        txn.0.rollback().await?;
        Ok(())
    }
}

impl Deref for TxnWrapper {
    type Target = DatabaseTransaction;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct ConnWrapper(DatabaseConnection);

#[async_trait]
impl TransactionManager for ConnWrapper {
    async fn begin_txn(&self) -> Result<TransactionWrapper, Box<dyn Error>> {
        let txn = self.0.begin().await?;
        Ok(TransactionWrapper::new(TxnWrapper(txn)))
    }
}

impl Deref for ConnWrapper {
    type Target = DatabaseConnection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for ConnWrapper {
    fn default() -> Self {
        ConnWrapper(get_default_db_connection())
    }
}

#[cfg(feature = "sqlite")]
pub fn get_default_db_connection() -> DatabaseConnection {
    futures::executor::block_on(async {
        Database::connect("sqlite::memory:")
            .await
            .expect("Error creating sqlite default connection")
    })
}

#[cfg(not(feature = "sqlite"))]
pub fn get_default_db_connection() -> DatabaseConnection {
    DatabaseConnection::default()
}

#[derive(Debug, Copy, Clone)]
pub enum MigrationAction {
    Up(Option<u32>),
    Down(Option<u32>),
    Fresh,
    Refresh,
    Reset,
}
