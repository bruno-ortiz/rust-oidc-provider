use std::sync::Arc;

use anyhow::anyhow;
use derive_new::new;
use oidc_types::jose::Algorithm;
use tracing::error;
use uuid::Uuid;

use oidc_types::pkce::CodeChallengeError;
use oidc_types::scopes::OPEN_ID;
use oidc_types::token::TokenResponse;
use oidc_types::token_request::AuthorisationCodeGrant;

use crate::claims::get_id_token_claims;
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::id_token_builder::IdTokenBuilder;
use crate::keystore::KeyUse;
use crate::manager::access_token_manager::AccessTokenManager;
use crate::manager::auth_code_manager::AuthorisationCodeManager;
use crate::manager::grant_manager::GrantManager;
use crate::manager::refresh_token_manager::RefreshTokenManager;
use crate::models::access_token::AccessToken;
use crate::models::client::AuthenticatedClient;
use crate::models::refresh_token::RefreshTokenBuilder;
use crate::models::Status;
use crate::persistence::TransactionId;
use crate::profile::ProfileData;
use crate::services::keystore::KeystoreService;
use crate::utils::resolve_sub;

#[derive(new)]
pub(crate) struct AuthorisationCodeGrantResolver {
    provider: Arc<OpenIDProviderConfiguration>,
    grant_manager: Arc<GrantManager>,
    access_token_manager: Arc<AccessTokenManager>,
    refresh_token_manager: Arc<RefreshTokenManager>,
    auth_code_manager: Arc<AuthorisationCodeManager>,
    keystore_service: Arc<KeystoreService>,
}

impl AuthorisationCodeGrantResolver {
    pub async fn execute(
        &self,
        grant_type: AuthorisationCodeGrant,
        client: AuthenticatedClient,
        txn: TransactionId,
    ) -> Result<TokenResponse, OpenIdError> {
        let clock = self.provider.clock_provider();
        let code = self
            .auth_code_manager
            .find(&grant_type.code)
            .await?
            .ok_or_else(|| OpenIdError::invalid_grant("Authorization code not found"))?;

        self.auth_code_manager.validate(&grant_type, &code)?;
        let grant = self
            .grant_manager
            .find_active(code.grant_id)
            .await?
            .ok_or_else(|| OpenIdError::invalid_grant("Invalid refresh Token"))?;

        if code.status != Status::Awaiting {
            self.grant_manager.consume(grant, txn.clone_some()).await?;
            return Err(OpenIdError::invalid_grant(
                "Authorization code already consumed",
            ));
        }
        let code = self
            .auth_code_manager
            .consume(code, txn.clone_some())
            .await?;
        if grant.client_id() != client.id() {
            return Err(OpenIdError::invalid_grant(
                "Client mismatch for Authorization Code",
            ));
        }
        if grant.redirect_uri().is_none() {
            return Err(OpenIdError::invalid_grant("Missing redirect_uri"));
        }
        if *grant.redirect_uri() != Some(grant_type.redirect_uri) {
            return Err(OpenIdError::invalid_grant("redirect_uri mismatch"));
        }

        let ttl = self.provider.ttl();
        let at_duration = ttl.access_token_ttl(client.as_ref());

        let mut access_token = AccessToken::bearer(
            clock.now(),
            grant.id(),
            at_duration,
            Some(code.scopes.clone()),
        );

        if let Some(thumbprint) = client.thumbprint() {
            access_token = access_token.with_thumbprint(thumbprint.clone())
        }
        let access_token = self
            .access_token_manager
            .save(access_token, txn.clone_some())
            .await
            .map_err(OpenIdError::server_error)?;

        let now = clock.now();
        let mut simple_id_token = None;
        if code.scopes.contains(&OPEN_ID) {
            let profile = ProfileData::get(&self.provider, &grant, client.as_ref())
                .await
                .map_err(OpenIdError::server_error)?;
            let claims = get_id_token_claims(&profile, grant.claims().as_ref())?;

            let alg = client.id_token_signing_alg();
            let keystore = self.keystore_service.server_keystore(client.as_ref(), alg);
            let signing_key = keystore
                .select(Some(KeyUse::Sig))
                .alg(alg.name())
                .first()
                .ok_or_else(|| {
                    let error = anyhow!("Missing signing key");
                    OpenIdError::server_error(error)
                })?;
            let sub = resolve_sub(&self.provider, grant.subject(), &client)
                .map_err(OpenIdError::server_error)?;
            let mut id_token_builder = IdTokenBuilder::new(signing_key)
                .with_issuer(self.provider.issuer())
                .with_sub(&sub)
                .with_audience(vec![client.id().into()])
                .with_exp(now + ttl.id_token)
                .with_iat(now)
                .with_nonce(code.nonce.as_ref())
                .with_s_hash(code.state.as_ref())?
                .with_c_hash(Some(&code.code))?
                .with_at_hash(Some(&access_token))?
                .with_custom_claims(claims);

            if grant.max_age().is_some() {
                id_token_builder = id_token_builder.with_auth_time(grant.auth_time())
            }

            let id_token = id_token_builder
                .build()
                .map_err(OpenIdError::server_error)?;

            simple_id_token = Some(
                id_token
                    .return_or_encrypt_simple_id_token(&self.keystore_service, &client)
                    .await
                    .map_err(OpenIdError::server_error)?,
            );
        }

        let mut rt = None;
        if self.provider.issue_refresh_token(&client).await {
            let rt_ttl = ttl.refresh_token_ttl(&client).await;
            let refresh_token = RefreshTokenBuilder::default()
                .token(Uuid::new_v4())
                .grant_id(code.grant_id)
                .nonce(code.nonce)
                .state(code.state)
                .scopes(code.scopes)
                .expires_in(rt_ttl)
                .created(now)
                .build()
                .map_err(OpenIdError::server_error)?;
            let refresh_token = self
                .refresh_token_manager
                .save(refresh_token, txn.clone_some())
                .await?;
            rt = Some(refresh_token.token)
        }

        Ok(TokenResponse::new(
            access_token.token,
            access_token.t_type,
            access_token.expires_in,
            rt,
            simple_id_token,
        ))
    }
}

impl From<CodeChallengeError> for OpenIdError {
    fn from(err: CodeChallengeError) -> Self {
        error!("Error creating code challenge, {:?}", err);
        OpenIdError::invalid_request(err.to_string())
    }
}
