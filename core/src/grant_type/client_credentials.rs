use std::collections::HashSet;

use anyhow::anyhow;
use async_trait::async_trait;

use oidc_types::acr::Acr;
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;
use oidc_types::token::TokenResponse;
use oidc_types::token_request::ClientCredentialsGrant;

use crate::configuration::clock::Clock;
use crate::configuration::credentials::ClientCredentialConfiguration;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::grant_type::GrantTypeResolver;
use crate::models::access_token::AccessToken;
use crate::models::client::{AuthenticatedClient, ClientInformation};
use crate::models::grant::GrantBuilder;

#[async_trait]
impl GrantTypeResolver for ClientCredentialsGrant {
    async fn execute(
        self,
        provider: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<TokenResponse, OpenIdError> {
        let clock = provider.clock_provider();
        let cc_config = provider.client_credentials();
        let ttl = provider.ttl();
        let scopes = if let Some(requested_scope) = self.scope {
            let client_info = client.as_ref();
            Some(validate_scopes(cc_config, requested_scope, client_info)?)
        } else {
            None
        };

        let grant = GrantBuilder::new()
            .subject(Subject::new(client.id()))
            .scopes(scopes.clone())
            .acr(Acr::default())
            .amr(None)
            .client_id(client.id())
            .auth_time(clock.now())
            .max_age(0)
            .redirect_uri(None)
            .rejected_claims(HashSet::new())
            .claims(None)
            .build()
            .expect("Should always build successfully");

        let at_duration = ttl.client_credentials_ttl(client.as_ref());
        let access_token =
            AccessToken::bearer(provider.clock_provider(), grant.id(), at_duration, scopes)
                .save(provider)
                .await
                .map_err(OpenIdError::server_error)?;
        Ok(TokenResponse::new(
            access_token.token,
            access_token.t_type,
            access_token.expires_in,
            None,
            None,
        ))
    }
}

fn validate_scopes(
    cc_config: &ClientCredentialConfiguration,
    requested_scope: Scopes,
    client_info: &ClientInformation,
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

    if !client_info.metadata().scope.contains_all(&requested_scope) {
        return Err(OpenIdError::invalid_scopes(&requested_scope));
    }
    Ok(requested_scope)
}
