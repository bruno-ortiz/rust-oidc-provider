use async_trait::async_trait;
use time::Duration;

use oidc_types::scopes::Scopes;
use oidc_types::token::TokenResponse;
use oidc_types::token_request::TokenRequestBody;

use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::access_token::AccessToken;
use crate::models::client::AuthenticatedClient;
use crate::models::grant::GrantID;
use crate::models::refresh_token::RefreshToken;

mod authorization_code;
mod client_credentials;
mod refresh_token;

#[async_trait]
pub trait GrantTypeResolver {
    async fn execute(
        self,
        provider: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<TokenResponse, OpenIdError>;
}

#[async_trait]
impl GrantTypeResolver for TokenRequestBody {
    async fn execute(
        self,
        provider: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<TokenResponse, OpenIdError> {
        let grant_type = self.grant_type();
        if !provider.grant_types_supported().contains(&grant_type) {
            return Err(OpenIdError::unsupported_grant_type(
                "The grant type is not supported by the authorization server",
            ));
        }
        if !client.as_ref().metadata().grant_types.contains(&grant_type) {
            return Err(OpenIdError::unauthorized_client(
                "The authenticated client is not authorized to use this authorization grant type",
            ));
        }
        match self {
            TokenRequestBody::AuthorisationCodeGrant(inner) => {
                inner.execute(provider, client).await
            }
            TokenRequestBody::RefreshTokenGrant(inner) => inner.execute(provider, client).await,
            TokenRequestBody::ClientCredentialsGrant(inner) => {
                inner.execute(provider, client).await
            }
        }
    }
}

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
