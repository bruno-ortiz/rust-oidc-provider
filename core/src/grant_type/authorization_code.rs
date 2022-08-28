use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::grant_type::GrantTypeResolver;
use async_trait::async_trait;
use oidc_types::access_token::AccessToken;
use oidc_types::client::AuthenticatedClient;
use oidc_types::token_request::AuthorisationCodeGrant;

#[async_trait]
impl GrantTypeResolver for AuthorisationCodeGrant {
    async fn execute(
        self,
        configuration: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<AccessToken, OpenIdError> {
        todo!()
    }
}
