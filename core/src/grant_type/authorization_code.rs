use anyhow::anyhow;
use async_trait::async_trait;
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
use crate::grant_type::{create_access_token, GrantTypeResolver};
use crate::id_token_builder::IdTokenBuilder;
use crate::keystore::KeyUse;
use crate::models::client::AuthenticatedClient;
use crate::models::grant::Grant;
use crate::models::refresh_token::RefreshTokenBuilder;
use crate::profile::ProfileData;

#[async_trait]
impl GrantTypeResolver for AuthorisationCodeGrant {
    async fn execute(self, client: AuthenticatedClient) -> Result<TokenResponse, OpenIdError> {
        let configuration = OpenIDProviderConfiguration::instance();
        let clock = configuration.clock_provider();
        let code = configuration
            .adapters()
            .code()
            .find(&self.code)
            .await
            .ok_or_else(|| OpenIdError::invalid_grant("Authorization code not found"))?
            .validate(&self)?
            .consume()
            .await?;

        let grant = Grant::find(code.grant_id)
            .await
            .ok_or_else(|| OpenIdError::invalid_grant("Invalid refresh Token"))?;

        if grant.client_id() != client.id() {
            return Err(OpenIdError::invalid_grant(
                "Client mismatch for refresh token",
            ));
        }
        if grant.redirect_uri().is_none() {
            return Err(OpenIdError::invalid_grant("Missing redirect_uri"));
        }
        if *grant.redirect_uri() != Some(self.redirect_uri) {
            return Err(OpenIdError::invalid_grant("redirect_uri mismatch"));
        }

        let ttl = configuration.ttl();
        let at_duration = ttl.access_token_ttl(client.as_ref());
        let access_token =
            create_access_token(grant.id(), at_duration, grant.scopes().clone()).await?;

        let now = clock.now();
        let mut simple_id_token = None;
        if grant.scopes().is_some() && grant.scopes().as_ref().unwrap().contains(&OPEN_ID) {
            let profile = ProfileData::get(&grant)
                .await
                .map_err(OpenIdError::server_error)?;
            let claims = get_id_token_claims(&profile, &grant)?;

            let alg = client.id_token_signing_alg();
            let keystore = client.as_ref().server_keystore(alg);
            let signing_key = keystore
                .select(KeyUse::Sig)
                .alg(alg.name())
                .first()
                .ok_or_else(|| {
                    let error = anyhow!("Missing signing key");
                    OpenIdError::server_error(error)
                })?;
            let id_token = IdTokenBuilder::new(signing_key)
                .with_issuer(configuration.issuer())
                .with_sub(grant.subject())
                .with_audience(vec![client.id().into()])
                .with_exp(now + ttl.id_token)
                .with_iat(now)
                .with_nonce(grant.nonce().as_ref())
                .with_s_hash(code.state.as_ref())?
                .with_c_hash(Some(&code.code))?
                .with_at_hash(Some(&access_token))?
                .with_custom_claims(claims)
                .build()
                .map_err(OpenIdError::server_error)?;
            simple_id_token = Some(
                id_token
                    .return_or_encrypt_simple_id_token(&client)
                    .await
                    .map_err(OpenIdError::server_error)?,
            );
        }

        let mut rt = None;
        if configuration.issue_refresh_token(&client).await {
            let rt_ttl = ttl.refresh_token_ttl(&client).await;
            let refresh_token = RefreshTokenBuilder::default()
                .token(Uuid::new_v4().to_string())
                .grant_id(code.grant_id)
                .state(code.state)
                .expires_in(now + rt_ttl)
                .created(now)
                .build()
                .map_err(OpenIdError::server_error)?
                .save()
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
