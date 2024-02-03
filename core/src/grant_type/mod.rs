use time::Duration;

use oidc_types::scopes::Scopes;

use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::access_token::AccessToken;
use crate::models::client::AuthenticatedClient;
use crate::models::grant::GrantID;
use crate::models::refresh_token::RefreshToken;

pub(crate) mod authorization_code;
pub(crate) mod client_credentials;
pub(crate) mod refresh_token;

async fn create_access_token(
    provider: &OpenIDProviderConfiguration,
    grant_id: GrantID,
    duration: Duration,
    scopes: Option<Scopes>,
) -> Result<AccessToken, OpenIdError> {
    AccessToken::bearer(provider.clock_provider(), grant_id, duration, scopes)
        .save(provider)
        .await
        .map_err(OpenIdError::server_error)
}

#[derive(Copy, Clone)]
pub struct RTContext<'a> {
    pub provider: &'a OpenIDProviderConfiguration,
    pub rt: &'a RefreshToken,
    pub client: &'a AuthenticatedClient,
}
