use std::sync::Arc;

use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait};

use oidc_core::adapter::{Adapter, PersistenceError};
use oidc_core::models::client::ClientInformation;
use oidc_core::persistence::TransactionWrapper;
use oidc_migration::async_trait::async_trait;
use oidc_types::client::ClientID;
use oidc_types::secret::HashedSecret;

use crate::entities::client_information::{ActiveModel, Model};
use crate::entities::prelude::ClientInformation as ClientEntity;
use crate::{insert_model, update_model, ConnWrapper};

#[derive(Clone)]
pub struct ClientRepository {
    db: Arc<ConnWrapper>,
    active_txn: Option<TransactionWrapper>,
}

impl ClientRepository {
    pub fn new(db: Arc<ConnWrapper>, active_txn: Option<TransactionWrapper>) -> Self {
        Self { db, active_txn }
    }

    fn build_active_model(item: ClientInformation) -> Result<ActiveModel, PersistenceError> {
        let model = ActiveModel {
            id: Set(item.id().as_ref().to_owned()),
            issue_date: Set(item.issue_date()),
            secret: Set(item.secret().to_string()),
            secret_expires_at: Set(item.secret_expires_at()),
            metadata: Set(item.metadata().to_json_value()?),
        };
        Ok(model)
    }
}

#[async_trait]
impl Adapter for ClientRepository {
    type Id = ClientID;
    type Item = ClientInformation;

    async fn find(&self, id: &Self::Id) -> Result<Option<Self::Item>, PersistenceError> {
        let model = ClientEntity::find_by_id(id.as_ref())
            .one(&self.db.0)
            .await
            .map_err(|err| PersistenceError::DB(err.into()))?;
        if let Some(model) = model {
            ClientInformation::try_from(model).map(Some)
        } else {
            Ok(None)
        }
    }

    //noinspection DuplicatedCode
    async fn insert(&self, item: Self::Item) -> Result<Self::Item, PersistenceError> {
        let model = Self::build_active_model(item)?;
        let saved_model = insert_model!(self, model);
        saved_model.try_into()
    }

    //noinspection DuplicatedCode
    async fn update(&self, item: Self::Item) -> Result<Self::Item, PersistenceError> {
        let model = Self::build_active_model(item)?;
        let updated = update_model!(self, model);
        updated.try_into()
    }
}

impl TryFrom<Model> for ClientInformation {
    type Error = PersistenceError;
    fn try_from(value: Model) -> Result<Self, Self::Error> {
        Ok(ClientInformation::new(
            ClientID::try_from(value.id)?,
            value.issue_date,
            HashedSecret::from(value.secret),
            value.secret_expires_at,
            serde_json::from_value(value.metadata)?,
        ))
    }
}
