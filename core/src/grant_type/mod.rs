mod authorization_code;
mod client_credentials;
mod refresh_token;

use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::access_token::AccessToken;
use async_trait::async_trait;
use oidc_types::client::AuthenticatedClient;
use oidc_types::token_request::TokenRequestBody;

#[async_trait]
pub trait GrantTypeResolver {
    async fn execute(
        self,
        configuration: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<AccessToken, OpenIdError>;
}

#[async_trait]
impl GrantTypeResolver for TokenRequestBody {
    async fn execute(
        self,
        configuration: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<AccessToken, OpenIdError> {
        let grant_type = self.grant_type();

        if !configuration.grant_types_supported().contains(&grant_type) {
            return Err(OpenIdError::unsupported_grant_type(
                "The grant type is not supported by the authorization server",
            ));
        }
        if !client.as_ref().metadata.grant_types.contains(&grant_type) {
            return Err(OpenIdError::unauthorized_client(
                "The authenticated client is not authorized to use this authorization grant type",
            ));
        }
        match self {
            TokenRequestBody::AuthorisationCodeGrant(inner) => {
                inner.execute(configuration, client).await
            }
            TokenRequestBody::RefreshTokenGrant(inner) => {
                inner.execute(configuration, client).await
            }
            TokenRequestBody::ClientCredentialsGrant(inner) => {
                inner.execute(configuration, client).await
            }
        }
    }
}
