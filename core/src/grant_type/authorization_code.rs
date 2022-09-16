use anyhow::anyhow;
use async_trait::async_trait;
use time::OffsetDateTime;
use tracing::error;
use uuid::Uuid;

use oidc_types::pkce::CodeChallengeError;
use oidc_types::scopes::OPEN_ID;
use oidc_types::token::TokenResponse;
use oidc_types::token_request::AuthorisationCodeGrant;

use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::grant_type::{create_access_token, GrantTypeResolver};
use crate::id_token_builder::IdTokenBuilder;
use crate::keystore::KeyUse;
use crate::models::client::AuthenticatedClient;
use crate::models::refresh_token::RefreshTokenBuilder;

#[async_trait]
impl GrantTypeResolver for AuthorisationCodeGrant {
    async fn execute(self, client: AuthenticatedClient) -> Result<TokenResponse, OpenIdError> {
        let configuration = OpenIDProviderConfiguration::instance();
        let grant = self;
        let code = configuration
            .adapters()
            .code()
            .find(&grant.code)
            .await
            .ok_or_else(|| OpenIdError::invalid_grant("Authorization code not found"))?
            .validate(&client, &grant)?
            .consume()
            .await?;

        let ttl = configuration.ttl();

        let at_duration = ttl.access_token_ttl(client.as_ref());
        let access_token = create_access_token(at_duration, code.scopes.clone()).await?;

        let mut id_token = None;
        if code.scopes.contains(&OPEN_ID) {
            let alg = client.id_token_signing_alg();
            let keystore = client.as_ref().server_keystore(alg);
            let signing_key = keystore
                .select(KeyUse::Sig)
                .alg(alg.name())
                .first()
                .ok_or_else(|| OpenIdError::server_error(anyhow!("Missing signing key")))?;
            id_token = Some(
                IdTokenBuilder::new(signing_key)
                    .with_issuer(configuration.issuer())
                    .with_sub(&code.subject)
                    .with_audience(vec![client.id().into()])
                    .with_exp(OffsetDateTime::now_utc() + ttl.id_token)
                    .with_iat(OffsetDateTime::now_utc())
                    .with_nonce(code.nonce.as_ref())
                    .with_s_hash(code.state.as_ref())?
                    .with_c_hash(Some(&code.code))?
                    .with_at_hash(Some(&access_token))?
                    .with_acr(&code.acr)
                    .with_amr(code.amr.as_ref())
                    .with_auth_time(code.auth_time)
                    .build()
                    .map_err(|err| OpenIdError::server_error(err.into()))?,
            );
        }

        let mut rt = None;
        if configuration.issue_refresh_token(&client).await {
            let rt_ttl = ttl.refresh_token_ttl(&client).await;
            let refresh_token = RefreshTokenBuilder::default()
                .token(Uuid::new_v4())
                .client_id(code.client_id)
                .redirect_uri(code.redirect_uri)
                .subject(code.subject)
                .scopes(code.scopes)
                .state(code.state)
                .amr(code.amr)
                .acr(code.acr)
                .nonce(code.nonce)
                .expires_in(OffsetDateTime::now_utc() + rt_ttl)
                .created(OffsetDateTime::now_utc())
                .auth_time(code.auth_time)
                .build()
                .map_err(|err| OpenIdError::server_error(err.into()))?
                .save()
                .await?;
            rt = Some(refresh_token.token.to_string())
        }

        Ok(TokenResponse::new(
            access_token.token,
            access_token.t_type,
            access_token.expires_in,
            rt,
            id_token,
        ))
    }
}

impl From<CodeChallengeError> for OpenIdError {
    fn from(err: CodeChallengeError) -> Self {
        error!("Error creating code challenge, {}", err);
        OpenIdError::invalid_request(err.to_string())
    }
}
