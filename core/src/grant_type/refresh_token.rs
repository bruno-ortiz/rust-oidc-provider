use anyhow::anyhow;
use async_trait::async_trait;

use oidc_types::scopes::OPEN_ID;
use oidc_types::token::TokenResponse;
use oidc_types::token_request::RefreshTokenGrant;

use crate::claims::get_id_token_claims;
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::grant_type::{create_access_token, GrantTypeResolver, RTContext};
use crate::id_token_builder::IdTokenBuilder;
use crate::keystore::KeyUse;
use crate::models::client::AuthenticatedClient;
use crate::models::grant::Grant;
use crate::models::refresh_token::RefreshToken;
use crate::profile::ProfileData;
use crate::utils::resolve_sub;

#[async_trait]
impl GrantTypeResolver for RefreshTokenGrant {
    async fn execute(
        self,
        provider: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<TokenResponse, OpenIdError> {
        let clock = provider.clock_provider();
        let grant_type = self;

        let mut refresh_token = provider
            .adapter()
            .refresh()
            .find(&grant_type.refresh_token)
            .await?
            .ok_or_else(|| OpenIdError::invalid_grant("Refresh token not found"))?;

        let grant = Grant::find(provider, refresh_token.grant_id)
            .await?
            .ok_or_else(|| OpenIdError::invalid_grant("Invalid refresh Token"))?;

        if grant.client_id() != client.id() {
            return Err(OpenIdError::invalid_grant(
                "Client mismatch for refresh token",
            ));
        }
        if let Err(err) = refresh_token.validate(provider) {
            // invalidate entire token chain
            grant.consume(provider).await?;
            return Err(err);
        }

        let context = RTContext {
            provider: provider,
            rt: &refresh_token,
            client: &client,
        };
        provider.validate_refresh_token(context).await?;
        let ttl = provider.ttl();

        let mut rt_token = None;
        if provider.rotate_refresh_token(context) {
            let old_rt = refresh_token.consume(provider).await?;
            refresh_token = RefreshToken::new_from(old_rt)?.save(provider).await?;
            rt_token = Some(refresh_token.token)
        }

        let at_duration = ttl.access_token_ttl(client.as_ref());
        let access_token = create_access_token(
            provider,
            grant.id(),
            at_duration,
            Some(refresh_token.scopes.clone()),
        )
        .await?;
        let mut simple_id_token = None;
        if refresh_token.scopes.contains(&OPEN_ID) {
            let profile = ProfileData::get(provider, &grant, client.as_ref())
                .await
                .map_err(OpenIdError::server_error)?;
            let claims = get_id_token_claims(&profile, grant.claims().as_ref())?;

            let alg = client.id_token_signing_alg();
            let keystore = client.as_ref().server_keystore(provider, alg);
            let signing_key = keystore
                .select(KeyUse::Sig)
                .alg(alg.name())
                .first()
                .ok_or_else(|| OpenIdError::server_error(anyhow!("Missing signing key")))?;
            let now = clock.now();
            let sub = resolve_sub(provider, grant.subject(), &client)
                .map_err(OpenIdError::server_error)?;
            let id_token = IdTokenBuilder::new(signing_key)
                .with_sub(&sub)
                .with_issuer(provider.issuer())
                .with_audience(vec![client.id().into()])
                .with_exp(now + ttl.id_token)
                .with_iat(now)
                .with_nonce(refresh_token.nonce.as_ref())
                .with_s_hash(refresh_token.state.as_ref())?
                .with_at_hash(Some(&access_token))?
                .with_custom_claims(claims)
                .build()
                .map_err(OpenIdError::server_error)?;

            simple_id_token = Some(
                id_token
                    .return_or_encrypt_simple_id_token(provider, &client)
                    .await
                    .map_err(OpenIdError::server_error)?,
            );
        }
        Ok(TokenResponse::new(
            access_token.token,
            access_token.t_type,
            access_token.expires_in,
            rt_token,
            simple_id_token,
        ))
    }
}
