use std::sync::Arc;

use anyhow::Context;
use oidc_types::token::TokenResponse;
use oidc_types::token_request::TokenRequestBody;
use uuid::Uuid;

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
use crate::models::access_token::{AccessToken, TokenError};
use crate::models::client::AuthenticatedClient;
use crate::models::refresh_token::RefreshToken;
use crate::models::token::{ActiveToken, Token, TokenByType, ACCESS_TOKEN, REFRESH_TOKEN};
use crate::services::keystore::KeystoreService;

pub struct TokenService {
    provider: Arc<OpenIDProviderConfiguration>,
    grant_manager: Arc<GrantManager>,
    access_token_manager: Arc<AccessTokenManager>,
    refresh_token_manager: Arc<RefreshTokenManager>,
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
        keystore_service: Arc<KeystoreService>,
    ) -> Self {
        TokenService {
            provider: provider.clone(),
            grant_manager: grant_manager.clone(),
            access_token_manager: access_token_manager.clone(),
            refresh_token_manager: refresh_token_manager.clone(),
            rt_grant_resolver: RefreshTokenGrantResolver::new(
                provider.clone(),
                grant_manager.clone(),
                access_token_manager.clone(),
                refresh_token_manager.clone(),
                keystore_service.clone(),
            ),
            auth_code_grant_resolver: AuthorisationCodeGrantResolver::new(
                provider.clone(),
                grant_manager.clone(),
                access_token_manager.clone(),
                refresh_token_manager.clone(),
                auth_code_manager.clone(),
                keystore_service.clone(),
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
        let txn_manager = self.provider.adapter().transaction_manager();
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
        let txn = txn_manager.begin_txn().await?;
        let token_response = match token_request_body {
            TokenRequestBody::AuthorisationCodeGrant(inner) => {
                self.auth_code_grant_resolver
                    .execute(inner, client, txn.clone())
                    .await
            }
            TokenRequestBody::RefreshTokenGrant(inner) => {
                self.rt_grant_resolver
                    .execute(inner, client, txn.clone())
                    .await
            }
            TokenRequestBody::ClientCredentialsGrant(inner) => {
                self.cc_grant_resolver
                    .execute(inner, client, txn.clone())
                    .await
            }
        }?;
        txn_manager.commit(txn).await?;
        Ok(token_response)
    }

    pub async fn find_active_token_by_type(
        &self,
        token: &str,
        token_type: &str,
    ) -> Result<ActiveToken<TokenByType>, TokenError> {
        let token = match token_type {
            ACCESS_TOKEN => self
                .find_access_token(token)
                .await?
                .map(TokenByType::Access),
            REFRESH_TOKEN => self
                .find_refresh_token(token)
                .await?
                .map(TokenByType::Refresh),
            _ => return Err(TokenError::InvalidTokenType(token_type.to_string())),
        };
        if let Some(token) = token {
            self.get_active_token(token).await
        } else {
            Err(TokenError::NotFound)
        }
    }

    pub async fn find_access_token(&self, token: &str) -> Result<Option<AccessToken>, TokenError> {
        let token = self
            .access_token_manager
            .find(token)
            .await
            .context("Failed to fetch access token")?;
        Ok(token)
    }

    pub async fn find_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<RefreshToken>, TokenError> {
        let rt = Uuid::parse_str(token).context("Failed to parse UUID")?;
        let token = self
            .refresh_token_manager
            .find(rt)
            .await
            .context("Failed to fetch refresh token")?;
        Ok(token)
    }
    pub async fn get_active_token<T: Token>(&self, token: T) -> Result<ActiveToken<T>, TokenError> {
        let now = self.provider.clock_provider().now();
        if now <= (token.created() + token.expires_in()) {
            let grant = self
                .grant_manager
                .find_active(token.grant_id())
                .await
                .context("Failed to fetch grant")?
                .ok_or(TokenError::InvalidGrant)?;
            Ok(ActiveToken::new(token, grant))
        } else {
            Err(TokenError::Expired)
        }
    }
}
