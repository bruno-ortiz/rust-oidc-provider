use std::sync::Arc;

use oidc_types::token::TokenResponse;
use oidc_types::token_request::TokenRequestBody;

use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::grant_type::authorization_code::AuthorisationCodeGrantResolver;
use crate::grant_type::client_credentials::ClientCredentialsGrantResolver;
use crate::grant_type::refresh_token::RefreshTokenGrantResolver;
use crate::manager::access_token_manager::AccessTokenManager;
use crate::manager::auth_code_manager::AuthorisationCodeManager;
use crate::manager::grant_manager::GrantManager;
use crate::manager::refresh_token_manager::RefreshTokenManager;
use crate::models::access_token::{AccessToken, ActiveAccessToken, TokenError};
use crate::models::client::AuthenticatedClient;

pub struct TokenService {
    provider: Arc<OpenIDProviderConfiguration>,
    grant_manager: Arc<GrantManager>,
    access_token_manager: Arc<AccessTokenManager>,
    rt_grant_resolver: RefreshTokenGrantResolver,
    auth_code_grant_resolver: AuthorisationCodeGrantResolver,
    cc_grant_resolver: ClientCredentialsGrantResolver,
}

impl TokenService {
    pub fn new(
        provider: Arc<OpenIDProviderConfiguration>,
        grant_manager: Arc<GrantManager>,
        access_token_manager: Arc<AccessTokenManager>,
        refresh_token_manager: Arc<RefreshTokenManager>,
        auth_code_manager: Arc<AuthorisationCodeManager>,
    ) -> Self {
        TokenService {
            provider: provider.clone(),
            grant_manager: grant_manager.clone(),
            access_token_manager: access_token_manager.clone(),
            rt_grant_resolver: RefreshTokenGrantResolver::new(
                provider.clone(),
                grant_manager.clone(),
                access_token_manager.clone(),
                refresh_token_manager.clone(),
            ),
            auth_code_grant_resolver: AuthorisationCodeGrantResolver::new(
                provider.clone(),
                grant_manager.clone(),
                access_token_manager.clone(),
                refresh_token_manager.clone(),
                auth_code_manager.clone(),
            ),
            cc_grant_resolver: ClientCredentialsGrantResolver::new(
                provider.clone(),
                grant_manager.clone(),
                access_token_manager.clone(),
            ),
        }
    }

    pub async fn execute(
        &self,
        token_request_body: TokenRequestBody,
        client: AuthenticatedClient,
    ) -> Result<TokenResponse, OpenIdError> {
        let grant_type = token_request_body.grant_type();
        if !self.provider.grant_types_supported().contains(&grant_type) {
            return Err(OpenIdError::unsupported_grant_type(
                "The grant type is not supported by the authorization server",
            ));
        }
        if !client.as_ref().metadata().grant_types.contains(&grant_type) {
            return Err(OpenIdError::unauthorized_client(
                "The authenticated client is not authorized to use this authorization grant type",
            ));
        }
        match token_request_body {
            TokenRequestBody::AuthorisationCodeGrant(inner) => {
                self.auth_code_grant_resolver.execute(inner, client).await
            }
            TokenRequestBody::RefreshTokenGrant(inner) => {
                self.rt_grant_resolver.execute(inner, client).await
            }
            TokenRequestBody::ClientCredentialsGrant(inner) => {
                self.cc_grant_resolver.execute(inner, client).await
            }
        }
    }

    pub async fn find(&self, bearer_token: &str) -> Result<AccessToken, TokenError> {
        let token = self
            .access_token_manager
            .find(bearer_token)
            .await?
            .ok_or_else(|| TokenError::InvalidAccessToken)?;
        Ok(token)
    }

    pub async fn as_active(&self, at: AccessToken) -> Result<ActiveAccessToken, TokenError> {
        let now = self.provider.clock_provider().now();
        if now <= (at.created + at.expires_in) {
            let grant = self
                .grant_manager
                .find(at.grant_id)
                .await?
                .ok_or(TokenError::InvalidGrant)?;
            Ok(ActiveAccessToken::new(at, grant))
        } else {
            Err(TokenError::Expired)
        }
    }
}
