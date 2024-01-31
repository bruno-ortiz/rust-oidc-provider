use std::sync::Arc;

use uuid::Uuid;

use oidc_types::client::ClientID;
use oidc_types::code::Code;

use crate::adapter::generic_adapter::InMemoryGenericAdapter;
use crate::adapter::Adapter;
use crate::models::access_token::AccessToken;
use crate::models::authorisation_code::AuthorisationCode;
use crate::models::client::ClientInformation;
use crate::models::grant::{Grant, GrantID};
use crate::models::refresh_token::RefreshToken;
use crate::persistence::{NoOpTransactionManager, TransactionManager};
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

pub trait AdapterContainer {
    fn transaction_manager(&self) -> Arc<dyn TransactionManager + Send + Sync>;
    fn code(&self) -> Arc<dyn Adapter<Item = AuthorisationCode, Id = Code> + Send + Sync>;
    fn grant(&self) -> Arc<dyn Adapter<Item = Grant, Id = GrantID> + Send + Sync>;
    fn refresh(&self) -> Arc<dyn Adapter<Item = RefreshToken, Id = Uuid> + Send + Sync>;
    fn token(&self) -> Arc<dyn Adapter<Item = AccessToken, Id = Uuid> + Send + Sync>;
    fn client(&self) -> Arc<dyn Adapter<Item = ClientInformation, Id = ClientID> + Send + Sync>;
    fn user(&self) -> Arc<dyn Adapter<Item = AuthenticatedUser, Id = SessionID> + Send + Sync>;
    fn interaction(&self) -> Arc<dyn Adapter<Item = Interaction, Id = Uuid> + Send + Sync>;
}

pub(crate) struct DefaultAdapterContainer {
    txn_manager: Arc<dyn TransactionManager + Send + Sync>,
    code: Arc<dyn Adapter<Item = AuthorisationCode, Id = Code> + Send + Sync>,
    grant: Arc<dyn Adapter<Item = Grant, Id = GrantID> + Send + Sync>,
    token: Arc<dyn Adapter<Item = AccessToken, Id = Uuid> + Send + Sync>,
    refresh: Arc<dyn Adapter<Item = RefreshToken, Id = Uuid> + Send + Sync>,
    client: Arc<dyn Adapter<Item = ClientInformation, Id = ClientID> + Send + Sync>,
    user: Arc<dyn Adapter<Item = AuthenticatedUser, Id = SessionID> + Send + Sync>,
    interaction: Arc<dyn Adapter<Item = Interaction, Id = Uuid> + Send + Sync>,
}

impl AdapterContainer for DefaultAdapterContainer {
    fn transaction_manager(&self) -> Arc<dyn TransactionManager + Send + Sync> {
        self.txn_manager.clone()
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

impl Default for DefaultAdapterContainer {
    fn default() -> Self {
        DefaultAdapterContainer {
            txn_manager: Arc::new(NoOpTransactionManager),
            code: Arc::new(InMemoryGenericAdapter::new()),
            grant: Arc::new(InMemoryGenericAdapter::new()),
            token: Arc::new(InMemoryGenericAdapter::new()),
            refresh: Arc::new(InMemoryGenericAdapter::new()),
            client: Arc::new(InMemoryGenericAdapter::new()),
            user: Arc::new(InMemoryGenericAdapter::new()),
            interaction: Arc::new(InMemoryGenericAdapter::new()),
        }
    }
}
