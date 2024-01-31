use std::str::FromStr;

use thiserror::Error;

use oidc_types::client::{ClientID, ParseError};

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::models::client::ClientInformation;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Error executing persistence operation: {}", .0)]
    Persistence(#[from] PersistenceError),
    #[error("Could not parse client id: {}", .0)]
    Parse(#[from] ParseError),
}

pub async fn retrieve_client_info(
    client_id: ClientID,
) -> Result<Option<ClientInformation>, ClientError> {
    let configuration = OpenIDProviderConfiguration::instance();
    Ok(configuration.adapter().client().find(&client_id).await?)
}

pub async fn retrieve_client_info_by_unparsed(
    client_id: &str,
) -> Result<Option<ClientInformation>, ClientError> {
    let client_id = ClientID::from_str(client_id)?;
    retrieve_client_info(client_id).await
}

pub async fn register_client(
    configuration: &OpenIDProviderConfiguration,
    client: ClientInformation,
) -> Result<(), ClientError> {
    let txn_manager = configuration.adapter().transaction_manager();
    let txn = txn_manager.begin_txn().await.unwrap();
    configuration
        .adapter()
        .client()
        .insert(client, txn.clone_self())
        .await?;
    txn_manager.commit(txn).await.unwrap();
    Ok(())
}
