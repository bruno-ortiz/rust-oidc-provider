use std::error::Error;
use std::ops::Deref;
use std::sync::Arc;

use anyhow::anyhow;
use dashmap::mapref::one::Ref;
use dashmap::DashMap;
pub use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sea_orm::{DatabaseTransaction, TransactionTrait};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task;
use tracing::{debug, error};
use uuid::Uuid;

use oidc_core::persistence::{TransactionId, TransactionManager};
use oidc_migration::async_trait::async_trait;

pub mod adapter;
mod entities;
mod repository;
mod utils;

const ROLLBACK_BUFFER: usize = 10;

struct ConnWrapper {
    conn: DatabaseConnection,
    transaction_map: Arc<DashMap<Uuid, DatabaseTransaction>>,
    rollback_channel: Sender<Uuid>,
}

impl ConnWrapper {
    pub fn new(conn: DatabaseConnection) -> Self {
        let (sender, receiver) = channel::<Uuid>(ROLLBACK_BUFFER);
        let transaction_map = Arc::new(DashMap::new());
        let wrapper = Self {
            conn,
            transaction_map: transaction_map.clone(),
            rollback_channel: sender,
        };
        wrapper.init_rollback_channel(receiver, transaction_map.clone());
        wrapper
    }

    fn init_rollback_channel(
        &self,
        mut rollback_receiver: Receiver<Uuid>,
        transaction_map: Arc<DashMap<Uuid, DatabaseTransaction>>,
    ) {
        task::spawn(async move {
            while let Some(txn_id) = rollback_receiver.recv().await {
                if let Some((_, txn)) = transaction_map.remove(&txn_id) {
                    if let Err(err) = txn.rollback().await {
                        error!(
                            "Error rolling back transaction with id: {} error: {}",
                            txn_id, err
                        )
                    }
                } else {
                    debug!("Transaction with id {:?} already finished", txn_id);
                }
            }
        });
    }

    pub fn get_txn(&self, id: &TransactionId) -> Option<Ref<Uuid, DatabaseTransaction>> {
        self.transaction_map.get(&id.id())
    }
}

#[async_trait]
impl TransactionManager for ConnWrapper {
    async fn begin_txn(&self) -> Result<TransactionId, Box<dyn Error>> {
        let txn = self.conn.begin().await?;
        let id = Uuid::new_v4();
        self.transaction_map.insert(id, txn);
        Ok(TransactionId::new(id, Some(self.rollback_channel.clone())))
    }

    async fn commit(&self, id: TransactionId) -> Result<(), Box<dyn Error>> {
        let (_, txn) = self
            .transaction_map
            .remove(&id.id())
            .ok_or(anyhow!("Transaction with id {:?} does not exist", id.id()))?;
        txn.commit().await?;
        Ok(())
    }

    async fn rollback(&self, id: TransactionId) -> Result<(), Box<dyn Error>> {
        let (_, txn) = self
            .transaction_map
            .remove(&id.id())
            .ok_or(anyhow!("Transaction with id {:?} does not exist", id.id()))?;
        txn.rollback().await?;
        Ok(())
    }
}

impl Deref for ConnWrapper {
    type Target = DatabaseConnection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl Default for ConnWrapper {
    fn default() -> Self {
        ConnWrapper::new(get_default_db_connection())
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
