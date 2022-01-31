use std::sync::Arc;

use oidc_types::client::{ClientID, ClientInformation};

use crate::adapter::Adapter;

pub struct ClientService {
    adapter: Arc<dyn Adapter<Item = ClientInformation>>,
}

impl ClientService {
    pub fn new(adapter: Arc<dyn Adapter<Item = ClientInformation>>) -> Self {
        ClientService { adapter }
    }

    pub async fn retrieve_client_info(&self, client_id: &ClientID) -> Option<ClientInformation> {
        self.adapter.find(client_id).await
    }
}
