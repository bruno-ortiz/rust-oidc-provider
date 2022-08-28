use crate::configuration::credentials::ClientCredentialConfiguration;
use crate::configuration::OpenIDProviderConfiguration;
use crate::response_type::errors::OpenIdError;
use anyhow::anyhow;
use async_trait::async_trait;
use oidc_types::access_token::{AccessToken, BEARER_TYPE};
use oidc_types::client::{AuthenticatedClient, ClientInformation};
use oidc_types::scopes::Scopes;
use oidc_types::token_request::{
    AuthorisationCodeGrant, ClientCredentialsGrant, RefreshTokenGrant, TokenRequestBody,
};

#[async_trait]
pub trait TokenRequestResolver {
    async fn execute(
        self,
        configuration: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<AccessToken, OpenIdError>;
}

#[async_trait]
impl TokenRequestResolver for RefreshTokenGrant {
    async fn execute(
        self,
        configuration: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<AccessToken, OpenIdError> {
        todo!()
    }
}

#[async_trait]
impl TokenRequestResolver for AuthorisationCodeGrant {
    async fn execute(
        self,
        configuration: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<AccessToken, OpenIdError> {
        todo!()
    }
}

#[async_trait]
impl TokenRequestResolver for ClientCredentialsGrant {
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
        let access_token = AccessToken::new(BEARER_TYPE, cc_config.duration, None, scopes);
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

#[async_trait]
impl TokenRequestResolver for TokenRequestBody {
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
        if !client.info_ref().metadata.grant_types.contains(&grant_type) {
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
