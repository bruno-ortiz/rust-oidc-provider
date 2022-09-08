use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::grant_type::GrantTypeResolver;
use crate::models::access_token::AccessToken;
use async_trait::async_trait;
use oidc_types::client::AuthenticatedClient;
use oidc_types::token::TokenResponse;
use oidc_types::token_request::RefreshTokenGrant;

#[async_trait]
impl GrantTypeResolver for RefreshTokenGrant {
    async fn execute(
        self,
        configuration: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<TokenResponse, OpenIdError> {
        todo!()
    }
}
