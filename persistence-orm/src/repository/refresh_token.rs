use std::sync::Arc;

use oidc_core::models::token::Token;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait, NotSet};
use uuid::Uuid;

use oidc_core::adapter::{Adapter, PersistenceError};
use oidc_core::models::grant::GrantID;
use oidc_core::models::refresh_token::{RefreshToken, RefreshTokenBuilder};
use oidc_core::models::Status;
use oidc_core::persistence::TransactionId;
use oidc_migration::async_trait::async_trait;
use oidc_types::nonce::Nonce;
use oidc_types::scopes::Scopes;
use oidc_types::state::State;

use crate::entities::prelude::Token as RefreshTokenEntity;
use crate::entities::sea_orm_active_enums::TokenType;
use crate::entities::token::{ActiveModel, Model};
use crate::{insert_model, update_model, ConnWrapper};

#[derive(Clone)]
pub struct RefreshTokenRepository {
    db: Arc<ConnWrapper>,
}

impl RefreshTokenRepository {
    pub fn new(db: Arc<ConnWrapper>) -> Self {
        Self { db }
    }

    fn build_active_model(item: RefreshToken) -> ActiveModel {
        let id: &[u8] = item.token.as_ref();
        let expires_in = item.created() + item.expires_in();
        let model = ActiveModel {
            token: Set(Vec::from(id)),
            grant_id: Set(Vec::from(item.grant_id.as_ref())),
            status: Set(item.status.into()),
            created: Set(item.created),
            expires_in: Set(expires_in),
            scopes: Set(item.scopes.to_string()),
            state: Set(item.state.map(|it| it.to_string())),
            nonce: Set(item.nonce.map(|it| it.to_string())),
            t_type: NotSet,
            certificate_thumbprint: NotSet,
            token_type: Set(TokenType::Refresh),
        };
        model
    }
}

#[async_trait]
impl Adapter for RefreshTokenRepository {
    type Id = Uuid;
    type Item = RefreshToken;

    async fn find(&self, id: &Self::Id) -> Result<Option<Self::Item>, PersistenceError> {
        let id: &[u8] = id.as_ref();
        let model = RefreshTokenEntity::find_by_id(id)
            .one(&self.db.conn)
            .await
            .map_err(|err| PersistenceError::DB(err.into()))?;
        if let Some(model) = model {
            RefreshToken::try_from(model).map(Some)
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

impl TryFrom<Model> for RefreshToken {
    type Error = PersistenceError;
    fn try_from(value: Model) -> Result<Self, Self::Error> {
        let scopes: Scopes = value.scopes.as_str().into();
        let expires_in = value.expires_in - value.created;
        let token = RefreshTokenBuilder::default()
            .token(Uuid::from_slice(&value.token)?)
            .scopes(scopes)
            .status(Status::from(value.status))
            .grant_id(GrantID::try_from(value.grant_id)?)
            .nonce(value.nonce.map(Nonce::new))
            .state(value.state.map(State::new))
            .created(value.created)
            .expires_in(expires_in)
            .build()
            .map_err(|err| PersistenceError::Internal(err.into()))?;
        Ok(token)
    }
}
