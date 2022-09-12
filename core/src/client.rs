use crate::adapter::PersistenceError;
use oidc_types::client::{ClientID, ClientInformation};
use std::str::FromStr;
use thiserror::Error;

use crate::configuration::OpenIDProviderConfiguration;
use crate::services::authorisation::AuthorisationError;

#[derive(Error, Debug)]
#[error("Error registering client")]
pub struct RegisterClientError {
    #[from]
    source: PersistenceError,
}

pub async fn retrieve_client_info(client_id: ClientID) -> Option<ClientInformation> {
    let configuration = OpenIDProviderConfiguration::instance();
    configuration.adapters().client().find(&client_id).await
}

pub async fn retrieve_client_info_by_unparsed(
    client_id: &str,
) -> Result<ClientInformation, AuthorisationError> {
    let client_id = ClientID::from_str(client_id)
        .map_err(|_| AuthorisationError::InvalidClient(client_id.to_owned()))?;
    let client = retrieve_client_info(client_id)
        .await
        .ok_or_else(|| AuthorisationError::InvalidClient(client_id.to_string()))?;
    Ok(client)
}

pub async fn register_client(
    configuration: &OpenIDProviderConfiguration,
    client: ClientInformation,
) -> Result<(), RegisterClientError> {
    configuration.adapters().client().save(client).await?;
    Ok(())
}
