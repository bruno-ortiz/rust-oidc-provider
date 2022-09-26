use anyhow::anyhow;
use async_trait::async_trait;
use time::OffsetDateTime;

use crate::claims::get_id_token_claims;
use oidc_types::scopes::OPEN_ID;
use oidc_types::simple_id_token::SimpleIdToken;
use oidc_types::token::TokenResponse;
use oidc_types::token_request::RefreshTokenGrant;

use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::grant_type::{create_access_token, GrantTypeResolver, RTContext};
use crate::id_token_builder::IdTokenBuilder;
use crate::keystore::KeyUse;
use crate::models::client::AuthenticatedClient;
use crate::models::refresh_token::RefreshToken;
use crate::profile::ProfileData;

#[async_trait]
impl GrantTypeResolver for RefreshTokenGrant {
    async fn execute(self, client: AuthenticatedClient) -> Result<TokenResponse, OpenIdError> {
        let configuration = OpenIDProviderConfiguration::instance();
        let grant = self;

        let mut refresh_token = configuration
            .adapters()
            .refresh()
            .find(&grant.refresh_token)
            .await
            .ok_or_else(|| OpenIdError::invalid_grant("Refresh token not found"))?
            .validate(&client)
            .await?;

        let context = RTContext {
            config: configuration,
            rt: &refresh_token,
            client: &client,
        };
        if let Err(err) = configuration.validate_refresh_token(context).await {
            return Err(err);
        };
        let ttl = configuration.ttl();

        let mut rt_token = None;
        if configuration.rotate_refresh_token(context) {
            let old_rt = refresh_token.consume().await?;
            refresh_token = RefreshToken::new_from(old_rt)?.save().await?;
            rt_token = Some(refresh_token.token.to_string())
        }
        let at_duration = ttl.access_token_ttl(client.as_ref());

        let access_token =
            create_access_token(client.id(), at_duration, refresh_token.scopes.clone()).await?;

        let mut id_token = None;
        if refresh_token.scopes.contains(&OPEN_ID) {
            let profile = ProfileData::get(&refresh_token)
                .await
                .map_err(OpenIdError::server_error)?;
            let claims = get_id_token_claims(&profile, &refresh_token)?;

            let alg = client.id_token_signing_alg();
            let keystore = client.as_ref().server_keystore(alg);
            let signing_key = keystore
                .select(KeyUse::Sig)
                .alg(alg.name())
                .first()
                .ok_or_else(|| OpenIdError::server_error(anyhow!("Missing signing key")))?;
            id_token = Some(
                IdTokenBuilder::new(signing_key)
                    .with_sub(&refresh_token.subject)
                    .with_issuer(configuration.issuer())
                    .with_audience(vec![client.id().into()])
                    .with_exp(OffsetDateTime::now_utc() + ttl.id_token)
                    .with_iat(OffsetDateTime::now_utc())
                    .with_nonce(refresh_token.nonce.as_ref())
                    .with_s_hash(refresh_token.state.as_ref())?
                    .with_at_hash(Some(&access_token))?
                    .with_custom_claims(claims)
                    .build()
                    .map_err(OpenIdError::server_error)?,
            );
        }
        Ok(TokenResponse::new(
            access_token.token,
            access_token.t_type,
            access_token.expires_in,
            rt_token,
            id_token.map(|it| SimpleIdToken::new(it.serialized())),
        ))
    }
}
