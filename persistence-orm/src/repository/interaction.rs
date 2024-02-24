use std::sync::Arc;

use anyhow::anyhow;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as b64engine;
use base64::Engine;
use sea_orm::ActiveValue::{Set, Unchanged};
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, NotSet};
use time::OffsetDateTime;
use uuid::Uuid;

use oidc_core::adapter::{Adapter, PersistenceError};
use oidc_core::authorisation_request::ValidatedAuthorisationRequest;
use oidc_core::persistence::TransactionId;
use oidc_core::services::types::Interaction;
use oidc_core::session::SessionID;
use oidc_core::user::AuthenticatedUser;
use oidc_migration::async_trait::async_trait;

use crate::entities::interaction::{ActiveModel, Model};
use crate::entities::prelude::AuthenticatedUser as UserEntity;
use crate::entities::prelude::Interaction as InteractionEntity;
use crate::entities::sea_orm_active_enums::InteractionType;
use crate::utils::db_err;
use crate::{insert_model, update_model, ConnWrapper};

#[derive(Clone)]
pub struct InteractionRepository {
    db: Arc<ConnWrapper>,
}

impl InteractionRepository {
    pub fn new(db: Arc<ConnWrapper>) -> Self {
        Self { db }
    }

    fn build_update_model(
        id: Uuid,
        session: SessionID,
        request: &ValidatedAuthorisationRequest,
        typ: InteractionType,
    ) -> Result<ActiveModel, PersistenceError> {
        let req = serde_json::to_string(&request)?;
        let encoded_req = b64engine.encode(req);
        Ok(ActiveModel {
            id: Unchanged(Vec::from(id.as_ref())),
            created: NotSet,
            session: Unchanged(Vec::from(session.as_ref())),
            request: Unchanged(encoded_req),
            interaction_type: Set(typ),
        })
    }

    async fn select_conn_and_convert(
        &self,
        model: Model,
        active_txn: Option<TransactionId>,
    ) -> Result<Interaction, PersistenceError> {
        if let Some(txn) = active_txn {
            let Some(txn_ref) = self.db.get_txn(&txn) else {
                return Err(PersistenceError::Internal(anyhow!(
                    "Invalid state, trying to use committed/cancelled transaction"
                )));
            };
            convert_from_model(txn_ref.value(), model).await
        } else {
            convert_from_model(&self.db.conn, model).await
        }
    }
}

#[async_trait]
impl Adapter for InteractionRepository {
    type Id = Uuid;
    type Item = Interaction;

    async fn find(&self, id: &Self::Id) -> Result<Option<Self::Item>, PersistenceError> {
        let model = InteractionEntity::find_by_id(id.as_ref())
            .one(&self.db.conn)
            .await
            .map_err(|err| PersistenceError::DB(err.into()))?;
        if let Some(model) = model {
            convert_from_model(&self.db.conn, model).await.map(Some)
        } else {
            Ok(None)
        }
    }

    async fn insert(
        &self,
        item: Self::Item,
        active_txn: Option<TransactionId>,
    ) -> Result<Self::Item, PersistenceError> {
        let model = match item {
            Interaction::Login {
                id,
                session,
                request,
                created,
            } => {
                let req = serde_json::to_string(&request)?;
                let encoded_req = b64engine.encode(req);
                ActiveModel {
                    id: Set(Vec::from(id.as_ref())),
                    created: Set(created),
                    session: Set(Vec::from(session.as_ref())),
                    request: Set(encoded_req),
                    interaction_type: Set(InteractionType::Login),
                }
            }

            Interaction::Consent {
                id,
                session,
                request,
                ..
            } => {
                let req = serde_json::to_string(&request)?;
                let encoded_req = b64engine.encode(req);
                ActiveModel {
                    id: Set(Vec::from(id.as_ref())),
                    created: Set(OffsetDateTime::now_utc()),
                    session: Set(Vec::from(session.as_ref())),
                    request: Set(encoded_req),
                    interaction_type: Set(InteractionType::Consent),
                }
            }
            Interaction::None {
                id,
                session,
                request,
                ..
            } => {
                let req = serde_json::to_string(&request)?;
                let encoded_req = b64engine.encode(req);
                ActiveModel {
                    id: Set(Vec::from(id.as_ref())),
                    created: Set(OffsetDateTime::now_utc()),
                    session: Set(Vec::from(session.as_ref())),
                    request: Set(encoded_req),
                    interaction_type: Set(InteractionType::None),
                }
            }
        };

        let saved_model = insert_model!(self, model, active_txn);
        self.select_conn_and_convert(saved_model, active_txn).await
    }

    async fn update(
        &self,
        item: Self::Item,
        active_txn: Option<TransactionId>,
    ) -> Result<Self::Item, PersistenceError> {
        let model = match item {
            Interaction::Consent {
                id,
                session,
                request,
                ..
            } => Self::build_update_model(id, session, &request, InteractionType::Consent)?,
            Interaction::None {
                id,
                session,
                request,
                ..
            } => Self::build_update_model(id, session, &request, InteractionType::None)?,
            _ => {
                return Err(PersistenceError::Internal(anyhow!(
                    "Invalid state cannot update interaction of Login type"
                )))
            }
        };
        let updated = update_model!(self, model, active_txn);
        self.select_conn_and_convert(updated, active_txn).await
    }
}

async fn convert_from_model(
    conn: &impl ConnectionTrait,
    value: Model,
) -> Result<Interaction, PersistenceError> {
    let request =
        serde_json::from_slice::<ValidatedAuthorisationRequest>(&b64engine.decode(value.request)?)?;

    let interaction = match value.interaction_type {
        InteractionType::Login => Interaction::login_with_id(
            Uuid::from_slice(&value.id)?,
            SessionID::try_from(value.session)?,
            request,
        ),
        InteractionType::Consent => {
            let user = get_user(conn, &value.id, &value.session).await?;
            Interaction::consent_with_id(Uuid::from_slice(&value.id)?, request, user)
        }
        InteractionType::None => {
            let user = get_user(conn, &value.id, &value.session).await?;
            Interaction::none_with_id(Uuid::from_slice(&value.id)?, request, user)
        }
    };

    Ok(interaction)
}

async fn get_user(
    conn: &impl ConnectionTrait,
    interaction_id: &[u8],
    session_id: &[u8],
) -> Result<AuthenticatedUser, PersistenceError> {
    let user: AuthenticatedUser = UserEntity::find_by_id(session_id)
        .one(conn)
        .await
        .map_err(db_err)?
        .map(|model| model.try_into())
        .transpose()?
        .ok_or_else(|| {
            PersistenceError::Internal(anyhow!(
                "Invalid state, user not found for interaction: {}",
                String::from_utf8_lossy(interaction_id)
            ))
        })?;
    Ok(user)
}
