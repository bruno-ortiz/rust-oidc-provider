use std::any::{Any, TypeId};
use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;

#[async_trait]
pub trait TransactionManager {
    async fn begin_txn(&self) -> Result<TransactionWrapper, Box<dyn Error>>;
}
#[derive(Clone)]
pub struct TransactionWrapper {
    transaction: Arc<dyn Transaction + Send + Sync>,
}

impl TransactionWrapper {
    pub fn new(txn: impl Any + Transaction + Send + Sync + 'static) -> Self {
        Self {
            transaction: Arc::new(txn),
        }
    }

    pub fn get<T: 'static>(&self) -> &T {
        match self.transaction.as_any().downcast_ref::<T>() {
            Some(t) => t,
            None => panic!(
                "Impossible to cast {:?} to {:?}",
                (*self.transaction).type_id(),
                TypeId::of::<T>()
            ),
        }
    }

    pub async fn commit(self) -> Result<(), Box<dyn Error>> {
        self.transaction.commit().await
    }

    pub async fn rollback(self) -> Result<(), Box<dyn Error>> {
        self.transaction.rollback().await
    }
}

#[async_trait]
pub trait Transaction: AsAny {
    async fn commit(mut self: Arc<Self>) -> Result<(), Box<dyn Error>>;
    async fn rollback(mut self: Arc<Self>) -> Result<(), Box<dyn Error>>;
}

pub trait AsAny: 'static {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Transaction> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct NoOpTransaction;

#[async_trait]
impl Transaction for NoOpTransaction {
    async fn commit(self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    async fn rollback(self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

#[derive(Default)]
pub struct NoOpTransactionManager;

#[async_trait]
impl TransactionManager for NoOpTransactionManager {
    async fn begin_txn(&self) -> Result<TransactionWrapper, Box<dyn Error>> {
        Ok(TransactionWrapper::new(NoOpTransaction))
    }
}
