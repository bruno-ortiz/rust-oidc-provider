use std::sync::Arc;

use uuid::Uuid;

use crate::access_token::AccessToken;
use oidc_types::client::{ClientID, ClientInformation};

use crate::adapter::generic_adapter::InMemoryGenericAdapter;
use crate::adapter::Adapter;
use crate::authorisation_code::AuthorisationCode;
use crate::services::interaction::Interaction;
use crate::session::AuthenticatedUser;

pub struct AdapterContainer {
    code: Arc<dyn Adapter<Item = AuthorisationCode, Id = String> + Send + Sync>,
    token: Arc<dyn Adapter<Item = AccessToken, Id = String> + Send + Sync>,
    client: Arc<dyn Adapter<Item = ClientInformation, Id = ClientID> + Send + Sync>,
    user: Arc<dyn Adapter<Item = AuthenticatedUser, Id = String> + Send + Sync>,
    interaction: Arc<dyn Adapter<Item = Interaction, Id = Uuid> + Send + Sync>,
}

impl AdapterContainer {
    pub fn code(&self) -> Arc<dyn Adapter<Item = AuthorisationCode, Id = String> + Send + Sync> {
        self.code.clone()
    }

    pub fn client(
        &self,
    ) -> Arc<dyn Adapter<Item = ClientInformation, Id = ClientID> + Send + Sync> {
        self.client.clone()
    }

    pub fn user(&self) -> Arc<dyn Adapter<Item = AuthenticatedUser, Id = String> + Send + Sync> {
        self.user.clone()
    }

    pub fn interaction(&self) -> Arc<dyn Adapter<Item = Interaction, Id = Uuid>> {
        self.interaction.clone()
    }
}

impl Default for AdapterContainer {
    fn default() -> Self {
        AdapterContainer {
            code: Arc::new(InMemoryGenericAdapter::new()),
            token: Arc::new(InMemoryGenericAdapter::new()),
            client: Arc::new(InMemoryGenericAdapter::new()),
            user: Arc::new(InMemoryGenericAdapter::new()),
            interaction: Arc::new(InMemoryGenericAdapter::new()),
        }
    }
}
