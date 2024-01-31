use std::sync::Arc;

use sea_orm::ActiveValue::{Set, Unchanged};
use sea_orm::{ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, NotSet, QueryFilter};

use oidc_core::adapter::{Adapter, PersistenceError};
use oidc_core::models::authorisation_code::AuthorisationCode;
use oidc_core::models::grant::GrantID;
use oidc_core::persistence::TransactionId;
use oidc_migration::async_trait::async_trait;
use oidc_types::code::Code;
use oidc_types::nonce::Nonce;
use oidc_types::pkce::CodeChallenge;
use oidc_types::state::State;

use crate::entities::authorisation_code::Model;
use crate::entities::authorisation_code::{ActiveModel, Column};
use crate::entities::prelude::AuthorisationCode as CodeEntity;
use crate::{insert_model, update_model, ConnWrapper};

#[derive(Clone)]
pub struct AuthorisationCodeRepository {
    db: Arc<ConnWrapper>,
}

impl AuthorisationCodeRepository {
    pub fn new(db: Arc<ConnWrapper>) -> Self {
        Self { db }
    }

    fn build_active_model(id: ActiveValue<i64>, item: AuthorisationCode) -> ActiveModel {
        let model = ActiveModel {
            id,
            code: Set(item.code.to_string()),
            status: Set(item.status.into()),
            scopes: Set(item.scopes.to_string()),
            expires_in: Set(item.expires_in),
            state: Set(item.state.map(|it| it.to_string())),
            nonce: Set(item.nonce.map(|it| it.to_string())),
            code_challenge: Set(item.code_challenge.map(|it| it.to_string())),
            code_challenge_method: Set(item.code_challenge_method.map(Into::into)),
            grant_id: Set(Vec::from(item.grant_id.as_ref())),
        };
        model
    }
}

#[async_trait]
impl Adapter for AuthorisationCodeRepository {
    type Id = Code;
    type Item = AuthorisationCode;

    async fn find(&self, id: &Self::Id) -> Result<Option<Self::Item>, PersistenceError> {
        let model = CodeEntity::find()
            .filter(Column::Code.eq(id.as_ref()))
            .one(&self.db.conn)
            .await
            .map_err(|err| PersistenceError::DB(err.into()))?;
        if let Some(model) = model {
            AuthorisationCode::try_from(model).map(Some)
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
        let model = Self::build_active_model(NotSet, item);
        let saved_model = insert_model!(self, model, active_txn);
        saved_model.try_into()
    }

    //noinspection DuplicatedCode
    async fn update(
        &self,
        item: Self::Item,
        active_txn: Option<TransactionId>,
    ) -> Result<Self::Item, PersistenceError> {
        let model = Self::build_active_model(Unchanged(item.id.unwrap_or_default() as i64), item);
        let updated = update_model!(self, model, active_txn);
        updated.try_into()
    }
}

impl TryFrom<Model> for AuthorisationCode {
    type Error = PersistenceError;
    fn try_from(value: Model) -> Result<Self, Self::Error> {
        Ok(AuthorisationCode {
            id: Some(value.id as u64),
            code: Code::from(value.code),
            grant_id: GrantID::try_from(value.grant_id)?,
            status: value.status.into(),
            code_challenge: value.code_challenge.map(CodeChallenge::new),
            code_challenge_method: value.code_challenge_method.map(Into::into),
            expires_in: value.expires_in,
            nonce: value.nonce.map(Nonce::new),
            state: value.state.map(State::new),
            scopes: value.scopes.as_str().into(),
        })
    }
}
