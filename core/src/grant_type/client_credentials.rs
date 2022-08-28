use crate::configuration::credentials::ClientCredentialConfiguration;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::grant_type::GrantTypeResolver;
use anyhow::anyhow;
use async_trait::async_trait;
use oidc_types::access_token::AccessToken;
use oidc_types::client::{AuthenticatedClient, ClientInformation};
use oidc_types::scopes::Scopes;
use oidc_types::token_request::ClientCredentialsGrant;

#[async_trait]
impl GrantTypeResolver for ClientCredentialsGrant {
    async fn execute(
        self,
        configuration: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<AccessToken, OpenIdError> {
        let cc_config = configuration.client_credentials();
        let scopes = if let Some(requested_scope) = self.scope {
            let client_info = client.info();
            Some(validate_scopes(cc_config, requested_scope, client_info)?)
        } else {
            None
        };
        let access_token =
            AccessToken::new(AccessToken::BEARER_TYPE, cc_config.duration, None, scopes);
        let access_token = configuration
            .adapters()
            .token()
            .save(access_token)
            .await
            .map_err(|err| OpenIdError::server_error(err.into()))?;
        Ok(access_token)
    }
}

fn validate_scopes(
    cc_config: &ClientCredentialConfiguration,
    requested_scope: Scopes,
    client_info: ClientInformation,
) -> Result<Scopes, OpenIdError> {
    if let Some(ref allowed_scopes) = cc_config.allowed_scopes {
        if !allowed_scopes.contains_all(&requested_scope) {
            return Err(OpenIdError::invalid_scopes(&requested_scope));
        }
    } else {
        return Err(OpenIdError::server_error(anyhow!(
            "Scopes not allowed in client credentials request"
        )));
    }

    if !client_info.metadata.scope.contains_all(&requested_scope) {
        return Err(OpenIdError::invalid_scopes(&requested_scope));
    }
    Ok(requested_scope)
}
