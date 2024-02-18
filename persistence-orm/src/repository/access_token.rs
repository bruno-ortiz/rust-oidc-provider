use std::sync::Arc;

use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait, NotSet};
use uuid::Uuid;

use oidc_core::adapter::{Adapter, PersistenceError};
use oidc_core::models::access_token::AccessToken;
use oidc_core::models::grant::GrantID;
use oidc_core::models::Status;
use oidc_core::persistence::TransactionId;
use oidc_migration::async_trait::async_trait;
use oidc_types::certificate::CertificateThumbprint;
use oidc_types::scopes::Scopes;

use crate::entities::prelude::Token as AccessTokenEntity;
use crate::entities::sea_orm_active_enums::TokenType;
use crate::entities::token::{ActiveModel, Model};
use crate::{insert_model, update_model, ConnWrapper};

#[derive(Clone)]
pub struct AccessTokenRepository {
    db: Arc<ConnWrapper>,
}

impl AccessTokenRepository {
    pub fn new(db: Arc<ConnWrapper>) -> Self {
        Self { db }
    }

    fn build_active_model(item: AccessToken) -> ActiveModel {
        let expires_in = item.created + item.expires_in;
        let model = ActiveModel {
            token: Set(Vec::from(item.token.as_ref())),
            grant_id: Set(Vec::from(item.grant_id.as_ref())),
            status: Set(Status::Awaiting.into()),
            created: Set(item.created),
            expires_in: Set(expires_in),
            scopes: Set(item.scopes.map(|s| s.to_string()).unwrap_or_default()),
            state: NotSet,
            nonce: NotSet,
            t_type: Set(Some(item.t_type)),
            token_type: Set(TokenType::Access),
            certificate_thumbprint: Set(item.certificate_thumbprint.map(|t| t.into())),
        };
        model
    }
}

#[async_trait]
impl Adapter for AccessTokenRepository {
    type Id = Uuid;
    type Item = AccessToken;

    async fn find(&self, id: &Self::Id) -> Result<Option<Self::Item>, PersistenceError> {
        let model = AccessTokenEntity::find_by_id(id.as_ref())
            .one(&self.db.conn)
            .await
            .map_err(|err| PersistenceError::DB(err.into()))?;
        if let Some(model) = model {
            AccessToken::try_from(model).map(Some)
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
        let model = Self::build_active_model(item);
        let saved_model = insert_model!(self, model, active_txn);
        saved_model.try_into()
    }

    //noinspection DuplicatedCode
    async fn update(
        &self,
        item: Self::Item,
        active_txn: Option<TransactionId>,
    ) -> Result<Self::Item, PersistenceError> {
        let model = Self::build_active_model(item);
        let updated = update_model!(self, model, active_txn);
        updated.try_into()
    }
}

impl TryFrom<Model> for AccessToken {
    type Error = PersistenceError;
    fn try_from(value: Model) -> Result<Self, Self::Error> {
        let scopes: Scopes = value.scopes.as_str().into();
        let expires_in = value.expires_in - value.created;
        let mut token = AccessToken::new_with_value(
            Uuid::from_slice(&value.token)?,
            value.t_type.unwrap_or("Bearer".to_string()),
            value.created,
            expires_in,
            Some(scopes),
            GrantID::try_from(value.grant_id)?,
        );
        if let Some(ct) = value.certificate_thumbprint {
            token = token.with_thumbprint(CertificateThumbprint::new(ct))
        }
        Ok(token)
    }
}
