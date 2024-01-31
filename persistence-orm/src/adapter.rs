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
use oidc_core::persistence::TransactionManager;
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
use crate::{ConnWrapper, MigrationAction};

pub struct SeaOrmAdapterContainer {
    db: Arc<ConnWrapper>,
    code: Arc<dyn Adapter<Item = AuthorisationCode, Id = Code> + Send + Sync>,
    grant: Arc<dyn Adapter<Item = Grant, Id = GrantID> + Send + Sync>,
    token: Arc<dyn Adapter<Item = AccessToken, Id = Uuid> + Send + Sync>,
    refresh: Arc<dyn Adapter<Item = RefreshToken, Id = Uuid> + Send + Sync>,
    client: Arc<dyn Adapter<Item = ClientInformation, Id = ClientID> + Send + Sync>,
    user: Arc<dyn Adapter<Item = AuthenticatedUser, Id = SessionID> + Send + Sync>,
    interaction: Arc<dyn Adapter<Item = Interaction, Id = Uuid> + Send + Sync>,
}

impl SeaOrmAdapterContainer {
    pub async fn new<C>(opts: C) -> anyhow::Result<Self>
    where
        C: Into<ConnectOptions>,
    {
        let conn = Database::connect(opts).await?;
        let conn_wrapper = Arc::new(ConnWrapper::new(conn));
        Ok(Self {
            db: conn_wrapper.clone(),
            code: Arc::new(AuthorisationCodeRepository::new(conn_wrapper.clone())),
            grant: Arc::new(GrantRepository::new(conn_wrapper.clone())),
            token: Arc::new(AccessTokenRepository::new(conn_wrapper.clone())),
            refresh: Arc::new(RefreshTokenRepository::new(conn_wrapper.clone())),
            client: Arc::new(ClientRepository::new(conn_wrapper.clone())),
            user: Arc::new(AuthenticatedUserRepository::new(conn_wrapper.clone())),
            interaction: Arc::new(InteractionRepository::new(conn_wrapper.clone())),
        })
    }

    pub async fn run_migrations(&self, action: MigrationAction) -> anyhow::Result<()> {
        match action {
            MigrationAction::Up(steps) => Migrator::up(&self.db.conn, steps).await?,
            MigrationAction::Down(steps) => Migrator::down(&self.db.conn, steps).await?,
            MigrationAction::Fresh => Migrator::fresh(&self.db.conn).await?,
            MigrationAction::Refresh => Migrator::refresh(&self.db.conn).await?,
            MigrationAction::Reset => Migrator::reset(&self.db.conn).await?,
        }
        Ok(())
    }
}

impl AdapterContainer for SeaOrmAdapterContainer {
    fn transaction_manager(&self) -> Arc<dyn TransactionManager + Send + Sync> {
        self.db.clone()
    }

    fn code(&self) -> Arc<dyn Adapter<Item = AuthorisationCode, Id = Code> + Send + Sync> {
        self.code.clone()
    }

    fn grant(&self) -> Arc<dyn Adapter<Item = Grant, Id = GrantID> + Send + Sync> {
        self.grant.clone()
    }

    fn refresh(&self) -> Arc<dyn Adapter<Item = RefreshToken, Id = Uuid> + Send + Sync> {
        self.refresh.clone()
    }

    fn token(&self) -> Arc<dyn Adapter<Item = AccessToken, Id = Uuid> + Send + Sync> {
        self.token.clone()
    }

    fn client(&self) -> Arc<dyn Adapter<Item = ClientInformation, Id = ClientID> + Send + Sync> {
        self.client.clone()
    }

    fn user(&self) -> Arc<dyn Adapter<Item = AuthenticatedUser, Id = SessionID> + Send + Sync> {
        self.user.clone()
    }

    fn interaction(&self) -> Arc<dyn Adapter<Item = Interaction, Id = Uuid> + Send + Sync> {
        self.interaction.clone()
    }
}

impl Default for SeaOrmAdapterContainer {
    fn default() -> Self {
        let conn_wrapper = Arc::new(ConnWrapper::default());
        SeaOrmAdapterContainer {
            db: conn_wrapper.clone(),
            code: Arc::new(AuthorisationCodeRepository::new(conn_wrapper.clone())),
            grant: Arc::new(GrantRepository::new(conn_wrapper.clone())),
            token: Arc::new(AccessTokenRepository::new(conn_wrapper.clone())),
            refresh: Arc::new(RefreshTokenRepository::new(conn_wrapper.clone())),
            client: Arc::new(ClientRepository::new(conn_wrapper.clone())),
            user: Arc::new(AuthenticatedUserRepository::new(conn_wrapper.clone())),
            interaction: Arc::new(InteractionRepository::new(conn_wrapper.clone())),
        }
    }
}
