use crate::configuration::OpenIDProviderConfiguration;
use crate::models::client::AuthenticatedClient;
use crate::models::refresh_token::RefreshToken;

pub(crate) mod authorization_code;
pub(crate) mod client_credentials;
pub(crate) mod refresh_token;

#[derive(Copy, Clone)]
pub struct RTContext<'a> {
    pub provider: &'a OpenIDProviderConfiguration,
    pub rt: &'a RefreshToken,
    pub client: &'a AuthenticatedClient,
}
