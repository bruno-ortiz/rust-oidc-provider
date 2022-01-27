use std::sync::Arc;

use oidc_types::client::{ClientID, ClientInformation};

use crate::configuration::OpenIDProviderConfiguration;

pub struct ClientService {
    configuration: Arc<OpenIDProviderConfiguration>,
}

impl ClientService {
    fn new(configuration: Arc<OpenIDProviderConfiguration>) -> Self {
        ClientService { configuration }
    }

    pub async fn retrieve_client_info(
        &self,
        client_id: &ClientID,
        config: &OpenIDProviderConfiguration,
    ) -> Option<ClientInformation> {
        unimplemented!("")
    }
}
