use std::sync::Arc;

use uuid::Uuid;

use oidc_types::client::{ClientID, ClientInformation};

use crate::adapter::client_adapter::InMemoryClientAdapter;
use crate::adapter::code_adapter::InMemoryAuthorisationCodeAdapter;
use crate::adapter::interaction_adapter::InMemoryInteractionAdapter;
use crate::adapter::user_adapter::InMemoryUserAdapter;
use crate::adapter::Adapter;
use crate::authorisation_code::AuthorisationCode;
use crate::services::interaction::Interaction;
use crate::session::AuthenticatedUser;

pub struct AdapterContainer {
    code: Arc<dyn Adapter<Item = AuthorisationCode, Id = String> + Send + Sync>,
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

    pub fn user(&self) -> Arc<dyn Adapter<Item = AuthenticatedUser, Id = String>> {
        self.user.clone()
    }

    pub fn interaction(&self) -> Arc<dyn Adapter<Item = Interaction, Id = Uuid>> {
        self.interaction.clone()
    }
}

impl Default for AdapterContainer {
    fn default() -> Self {
        AdapterContainer {
            code: Arc::new(InMemoryAuthorisationCodeAdapter::new()),
            client: Arc::new(InMemoryClientAdapter::new()),
            user: Arc::new(InMemoryUserAdapter::new()),
            interaction: Arc::new(InMemoryInteractionAdapter::new()),
        }
    }
}
