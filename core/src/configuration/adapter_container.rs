use std::sync::Arc;

use uuid::Uuid;

use oidc_types::client::ClientID;
use oidc_types::code::Code;

use crate::adapter::generic_adapter::InMemoryGenericAdapter;
use crate::adapter::Adapter;
use crate::models::access_token::AccessToken;
use crate::models::authorisation_code::AuthorisationCode;
use crate::models::client::ClientInformation;
use crate::models::refresh_token::RefreshToken;
use crate::services::types::Interaction;
use crate::user::AuthenticatedUser;

pub struct AdapterContainer {
    code: Arc<dyn Adapter<Item = AuthorisationCode, Id = Code> + Send + Sync>,
    token: Arc<dyn Adapter<Item = AccessToken, Id = String> + Send + Sync>,
    refresh: Arc<dyn Adapter<Item = RefreshToken, Id = String> + Send + Sync>,
    client: Arc<dyn Adapter<Item = ClientInformation, Id = ClientID> + Send + Sync>,
    user: Arc<dyn Adapter<Item = AuthenticatedUser, Id = String> + Send + Sync>,
    interaction: Arc<dyn Adapter<Item = Interaction, Id = Uuid> + Send + Sync>,
}

impl AdapterContainer {
    pub fn code(&self) -> Arc<dyn Adapter<Item = AuthorisationCode, Id = Code> + Send + Sync> {
        self.code.clone()
    }

    pub fn refresh(&self) -> Arc<dyn Adapter<Item = RefreshToken, Id = String> + Send + Sync> {
        self.refresh.clone()
    }

    pub fn token(&self) -> Arc<dyn Adapter<Item = AccessToken, Id = String> + Send + Sync> {
        self.token.clone()
    }

    pub fn client(
        &self,
    ) -> Arc<dyn Adapter<Item = ClientInformation, Id = ClientID> + Send + Sync> {
        self.client.clone()
    }

    pub fn user(&self) -> Arc<dyn Adapter<Item = AuthenticatedUser, Id = String> + Send + Sync> {
        self.user.clone()
    }

    pub fn interaction(&self) -> Arc<dyn Adapter<Item = Interaction, Id = Uuid> + Send + Sync> {
        self.interaction.clone()
    }
}

impl Default for AdapterContainer {
    fn default() -> Self {
        AdapterContainer {
            code: Arc::new(InMemoryGenericAdapter::new()),
            token: Arc::new(InMemoryGenericAdapter::new()),
            refresh: Arc::new(InMemoryGenericAdapter::new()),
            client: Arc::new(InMemoryGenericAdapter::new()),
            user: Arc::new(InMemoryGenericAdapter::new()),
            interaction: Arc::new(InMemoryGenericAdapter::new()),
        }
    }
}
