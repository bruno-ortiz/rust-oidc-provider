use std::collections::HashSet;
use std::sync::Arc;

use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait};
use url::Url;

use oidc_core::adapter::{Adapter, PersistenceError};
use oidc_core::models::grant::{Grant, GrantBuilder, GrantID};
use oidc_core::persistence::TransactionId;
use oidc_migration::async_trait::async_trait;
use oidc_types::amr::Amr;
use oidc_types::claims::Claims;
use oidc_types::client::ClientID;

use crate::entities::grant::{ActiveModel, Model};
use crate::entities::prelude::Grant as GrantEntity;
use crate::{insert_model, update_model, ConnWrapper};

#[derive(Clone)]
pub struct GrantRepository {
    db: Arc<ConnWrapper>,
}

impl GrantRepository {
    pub fn new(db: Arc<ConnWrapper>) -> Self {
        Self { db }
    }

    fn build_active_model(item: Grant) -> Result<ActiveModel, PersistenceError> {
        let claims = item
            .claims()
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let rejected_claims = serde_json::to_value(item.rejected_claims())?;
        let model = ActiveModel {
            id: Set(Vec::from(item.id().as_ref())),
            status: Set(item.status().into()),
            client_id: Set(Vec::from(item.client_id().as_ref())),
            subject: Set(item.subject().to_string()),
            auth_time: Set(item.auth_time()),
            max_age: Set(item.max_age().map(|ma| ma as i64)),
            redirect_uri: Set(item.redirect_uri().as_ref().map(|uri| uri.to_string())),
            scopes: Set(item.scopes().as_ref().map(|s| s.to_string())),
            acr: Set(item.acr().to_string()),
            amr: Set(item.amr().as_ref().map(|amr| amr.to_string())),
            claims: Set(claims),
            rejected_claims: Set(rejected_claims),
        };
        Ok(model)
    }
}

#[async_trait]
impl Adapter for GrantRepository {
    type Id = GrantID;
    type Item = Grant;

    async fn find(&self, id: &Self::Id) -> Result<Option<Self::Item>, PersistenceError> {
        let model = GrantEntity::find_by_id(id.as_ref())
            .one(&self.db.conn)
            .await
            .map_err(|err| PersistenceError::DB(err.into()))?;
        if let Some(model) = model {
            Grant::try_from(model).map(Some)
        } else {
            Ok(None)
        }
    }

    //noinspection DuplicatedCode
    async fn insert(
        &self,
        item: Self::Item,
        active_txn: Option<TransactionId>,
    ) -> Result<Self::Item, PersistenceError> {
        let model = Self::build_active_model(item)?;
        let saved_model = insert_model!(self, model, active_txn);
        saved_model.try_into()
    }

    //noinspection DuplicatedCode
    async fn update(
        &self,
        item: Self::Item,
        active_txn: Option<TransactionId>,
    ) -> Result<Self::Item, PersistenceError> {
        let model = Self::build_active_model(item)?;
        let updated = update_model!(self, model, active_txn);
        updated.try_into()
    }
}

impl TryFrom<Model> for Grant {
    type Error = PersistenceError;
    fn try_from(value: Model) -> Result<Self, Self::Error> {
        let claims = value
            .claims
            .map(serde_json::from_value::<Claims>)
            .transpose()?;
        let rejected_claims = serde_json::from_value::<HashSet<String>>(value.rejected_claims)?;

        let redirect_uri = value.redirect_uri.map(|uri| Url::parse(&uri)).transpose()?;
        let grant = GrantBuilder::new_with(GrantID::try_from(value.id)?, value.status.into())
            .client_id(ClientID::try_from(value.client_id)?)
            .scopes(value.scopes.map(|scope_str| scope_str.as_str().into()))
            .claims(claims)
            .rejected_claims(rejected_claims)
            .redirect_uri(redirect_uri)
            .max_age(value.max_age.map(|max_age| max_age as u64))
            .acr(value.acr)
            .amr(value.amr.map(Amr::from))
            .subject(value.subject)
            .auth_time(value.auth_time)
            .build()
            .map_err(|err| PersistenceError::Internal(err.into()))?;
        Ok(grant)
    }
}
