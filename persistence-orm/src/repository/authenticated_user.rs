use std::sync::Arc;

use sea_orm::prelude::Uuid;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait};

use oidc_core::adapter::{Adapter, PersistenceError};
use oidc_core::models::grant::GrantID;
use oidc_core::persistence::TransactionWrapper;
use oidc_core::session::SessionID;
use oidc_core::user::AuthenticatedUser;
use oidc_migration::async_trait::async_trait;
use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::subject::Subject;

use crate::entities::authenticated_user::{ActiveModel, Model};
use crate::entities::prelude::AuthenticatedUser as UserEntity;
use crate::{insert_model, update_model, ConnWrapper};

#[derive(Clone)]
pub struct AuthenticatedUserRepository {
    db: Arc<ConnWrapper>,
    active_txn: Option<TransactionWrapper>,
}

impl AuthenticatedUserRepository {
    pub fn new(db: Arc<ConnWrapper>, active_txn: Option<TransactionWrapper>) -> Self {
        Self { db, active_txn }
    }

    fn build_active_model(item: AuthenticatedUser) -> ActiveModel {
        let model = ActiveModel {
            session: Set(Vec::from(item.session().as_ref())),
            grant_id: Set(item.grant_id().as_ref().map(|id| Vec::from(id.as_ref()))),
            subject: Set(item.sub().to_string()),
            interaction_id: Set(Vec::from(item.interaction_id())),
            auth_time: Set(item.auth_time()),
            acr: Set(item.acr().to_string()),
            amr: Set(item.amr().map(|amr| amr.to_string())),
        };
        model
    }
}

#[async_trait]
impl Adapter for AuthenticatedUserRepository {
    type Id = SessionID;
    type Item = AuthenticatedUser;

    async fn find(&self, id: &Self::Id) -> Result<Option<Self::Item>, PersistenceError> {
        let model = UserEntity::find_by_id(id.as_ref())
            .one(&self.db.0)
            .await
            .map_err(|err| PersistenceError::DB(err.into()))?;
        if let Some(model) = model {
            AuthenticatedUser::try_from(model).map(Some)
        } else {
            Ok(None)
        }
    }

    //noinspection DuplicatedCode
    async fn insert(&self, item: Self::Item) -> Result<Self::Item, PersistenceError> {
        let model = Self::build_active_model(item);
        let saved_model = insert_model!(self, model);
        saved_model.try_into()
    }

    //noinspection DuplicatedCode
    async fn update(&self, item: Self::Item) -> Result<Self::Item, PersistenceError> {
        let model = Self::build_active_model(item);
        let updated = update_model!(self, model);
        updated.try_into()
    }
}

impl TryFrom<Model> for AuthenticatedUser {
    type Error = PersistenceError;
    fn try_from(value: Model) -> Result<Self, Self::Error> {
        let user = AuthenticatedUser::new(
            SessionID::try_from(value.session)?,
            Subject::new(value.subject),
            value.auth_time,
            Uuid::from_slice(&value.interaction_id)?,
            Some(Acr::from(value.acr)),
            value.amr.map(Amr::from),
        );
        let user = if let Some(grant_id) = value.grant_id {
            let grant_id = GrantID::try_from(grant_id)?;
            user.with_grant(grant_id)
        } else {
            user
        };
        Ok(user)
    }
}
