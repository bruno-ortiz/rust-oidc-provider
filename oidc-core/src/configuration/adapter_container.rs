use std::sync::Arc;

use oidc_types::client::ClientInformation;

use crate::adapter::client_adapter::InMemoryClientAdapter;
use crate::adapter::code_adapter::InMemoryAuthorisationCodeAdapter;
use crate::adapter::Adapter;
use crate::authorisation_code::AuthorisationCode;

#[derive(Debug)]
pub struct AdapterContainer {
    code: Arc<dyn Adapter<Item = AuthorisationCode> + Send + Sync>,
    client: Arc<dyn Adapter<Item = ClientInformation> + Send + Sync>,
}

impl AdapterContainer {
    pub fn code(&self) -> Arc<dyn Adapter<Item = AuthorisationCode>> {
        self.code.clone()
    }

    pub fn client(&self) -> Arc<dyn Adapter<Item = ClientInformation>> {
        self.client.clone()
    }
}

impl Default for AdapterContainer {
    fn default() -> Self {
        AdapterContainer {
            code: Arc::new(InMemoryAuthorisationCodeAdapter::new()),
            client: Arc::new(InMemoryClientAdapter::new()),
        }
    }
}
