use std::collections::HashSet;
use std::sync::Arc;

use anyhow::anyhow;
use derive_new::new;
use uuid::Uuid;

use oidc_types::acr::Acr;
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;
use oidc_types::token::TokenResponse;
use oidc_types::token_request::ClientCredentialsGrant;

use crate::configuration::clock::Clock;
use crate::configuration::credentials::ClientCredentialConfiguration;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::manager::access_token_manager::AccessTokenManager;
use crate::manager::grant_manager::GrantManager;
use crate::models::access_token::AccessToken;
use crate::models::client::{AuthenticatedClient, ClientInformation};
use crate::models::grant::{GrantBuilder, GrantID};
use crate::models::Status;
use crate::persistence::TransactionId;

#[derive(new)]
pub(crate) struct ClientCredentialsGrantResolver {
    provider: Arc<OpenIDProviderConfiguration>,
    grant_manager: Arc<GrantManager>,
    access_token_manager: Arc<AccessTokenManager>,
}

impl ClientCredentialsGrantResolver {
    pub async fn execute(
        &self,
        grant_type: ClientCredentialsGrant,
        client: AuthenticatedClient,
        txn: TransactionId,
    ) -> Result<TokenResponse, OpenIdError> {
        let clock = self.provider.clock_provider();
        let cc_config = self.provider.client_credentials();
        let ttl = self.provider.ttl();
        let scopes = if let Some(requested_scope) = grant_type.scope {
            let client_info = client.as_ref();
            Some(validate_scopes(cc_config, requested_scope, client_info)?)
        } else {
            None
        };

        let grant = GrantBuilder::new_with(GrantID::new(Uuid::new_v4()), Status::Consumed)
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

        let grant = self
            .grant_manager
            .save(grant, txn.clone_some())
            .await
            .map_err(OpenIdError::server_error)?;

        let at_duration = ttl.client_credentials_ttl(client.as_ref());
        let access_token = AccessToken::bearer(clock.now(), grant.id(), at_duration, scopes);
        let access_token = self
            .access_token_manager
            .save(access_token, txn.clone_some())
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
