use std::sync::Arc;

use sea_orm::prelude::Uuid;
use sea_orm::{ConnectOptions, Database};

use oidc_core::adapter::Adapter;
use oidc_core::configuration::adapter_container::AdapterContainer;
use oidc_core::models::access_token::AccessToken;
use oidc_core::models::authorisation_code::AuthorisationCode;
use oidc_core::models::client::ClientInformation;
use oidc_core::models::grant::{Grant, GrantID};
use oidc_core::models::refresh_token::RefreshToken;
use oidc_core::persistence::{TransactionManager, TransactionWrapper};
use oidc_core::services::types::Interaction;
use oidc_core::session::SessionID;
use oidc_core::user::AuthenticatedUser;
use oidc_migration::{Migrator, MigratorTrait};
use oidc_types::client::ClientID;
use oidc_types::code::Code;

use crate::repository::access_token::AccessTokenRepository;
use crate::repository::authenticated_user::AuthenticatedUserRepository;
use crate::repository::authorisation_code::AuthorisationCodeRepository;
use crate::repository::client::ClientRepository;
use crate::repository::grant::GrantRepository;
use crate::repository::interaction::InteractionRepository;
use crate::repository::refresh_token::RefreshTokenRepository;
use crate::{get_default_db_connection, ConnWrapper, MigrationAction};

pub struct SeaOrmAdapterContainer {
    db: Arc<ConnWrapper>,
}

impl SeaOrmAdapterContainer {
    pub async fn new<C>(opts: C) -> anyhow::Result<Self>
    where
        C: Into<ConnectOptions>,
    {
        let conn = Database::connect(opts).await?;
        Ok(Self {
            db: Arc::new(ConnWrapper(conn)),
        })
    }

    pub async fn run_migrations(&self, action: MigrationAction) -> anyhow::Result<()> {
        match action {
            MigrationAction::Up(steps) => Migrator::up(&self.db.0, steps).await?,
            MigrationAction::Down(steps) => Migrator::down(&self.db.0, steps).await?,
            MigrationAction::Fresh => Migrator::fresh(&self.db.0).await?,
            MigrationAction::Refresh => Migrator::refresh(&self.db.0).await?,
            MigrationAction::Reset => Migrator::reset(&self.db.0).await?,
        }
        Ok(())
    }
}

impl AdapterContainer for SeaOrmAdapterContainer {
    fn transaction_manager(&self) -> &dyn TransactionManager {
        self.db.as_ref()
    }

    fn code(
        &self,
        active_txn: Option<TransactionWrapper>,
    ) -> Arc<dyn Adapter<Item = AuthorisationCode, Id = Code> + Send + Sync> {
        if let Some(txn) = active_txn {
            Arc::new(AuthorisationCodeRepository::new(self.db.clone(), Some(txn)))
        } else {
            Arc::new(AuthorisationCodeRepository::new(self.db.clone(), None))
        }
    }

    fn grant(
        &self,
        active_txn: Option<TransactionWrapper>,
    ) -> Arc<dyn Adapter<Item = Grant, Id = GrantID> + Send + Sync> {
        if let Some(txn) = active_txn {
            Arc::new(GrantRepository::new(self.db.clone(), Some(txn)))
        } else {
            Arc::new(GrantRepository::new(self.db.clone(), None))
        }
    }

    fn refresh(
        &self,
        active_txn: Option<TransactionWrapper>,
    ) -> Arc<dyn Adapter<Item = RefreshToken, Id = Uuid> + Send + Sync> {
        if let Some(txn) = active_txn {
            Arc::new(RefreshTokenRepository::new(self.db.clone(), Some(txn)))
        } else {
            Arc::new(RefreshTokenRepository::new(self.db.clone(), None))
        }
    }

    fn token(
        &self,
        active_txn: Option<TransactionWrapper>,
    ) -> Arc<dyn Adapter<Item = AccessToken, Id = Uuid> + Send + Sync> {
        if let Some(txn) = active_txn {
            Arc::new(AccessTokenRepository::new(self.db.clone(), Some(txn)))
        } else {
            Arc::new(AccessTokenRepository::new(self.db.clone(), None))
        }
    }

    fn client(
        &self,
        active_txn: Option<TransactionWrapper>,
    ) -> Arc<dyn Adapter<Item = ClientInformation, Id = ClientID> + Send + Sync> {
        if let Some(txn) = active_txn {
            Arc::new(ClientRepository::new(self.db.clone(), Some(txn)))
        } else {
            Arc::new(ClientRepository::new(self.db.clone(), None))
        }
    }

    fn user(
        &self,
        active_txn: Option<TransactionWrapper>,
    ) -> Arc<dyn Adapter<Item = AuthenticatedUser, Id = SessionID> + Send + Sync> {
        if let Some(txn) = active_txn {
            Arc::new(AuthenticatedUserRepository::new(self.db.clone(), Some(txn)))
        } else {
            Arc::new(AuthenticatedUserRepository::new(self.db.clone(), None))
        }
    }

    fn interaction(
        &self,
        active_txn: Option<TransactionWrapper>,
    ) -> Arc<dyn Adapter<Item = Interaction, Id = Uuid> + Send + Sync> {
        if let Some(txn) = active_txn {
            Arc::new(InteractionRepository::new(self.db.clone(), Some(txn)))
        } else {
            Arc::new(InteractionRepository::new(self.db.clone(), None))
        }
    }
}

impl Default for SeaOrmAdapterContainer {
    fn default() -> Self {
        SeaOrmAdapterContainer {
            db: Arc::new(ConnWrapper(get_default_db_connection())),
        }
    }
}
