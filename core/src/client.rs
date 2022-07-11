use oidc_types::client::{ClientID, ClientInformation};

use crate::configuration::OpenIDProviderConfiguration;

pub async fn retrieve_client_info(
    configuration: &OpenIDProviderConfiguration,
    client_id: ClientID,
) -> Option<ClientInformation> {
    configuration.adapters().client().find(&client_id).await
}
