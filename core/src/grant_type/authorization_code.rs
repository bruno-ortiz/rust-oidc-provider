use async_trait::async_trait;
use time::OffsetDateTime;
use tracing::error;
use uuid::Uuid;

use oidc_types::client::AuthenticatedClient;
use oidc_types::pkce::{validate_pkce, CodeChallengeError};
use oidc_types::token_request::AuthorisationCodeGrant;

use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::grant_type::GrantTypeResolver;
use crate::models::access_token::AccessToken;
use crate::models::authorisation_code::{AuthorisationCode, CodeStatus};
use crate::models::refresh_token::RefreshTokenBuilder;

#[async_trait]
impl GrantTypeResolver for AuthorisationCodeGrant {
    async fn execute(
        self,
        configuration: &OpenIDProviderConfiguration,
        client: AuthenticatedClient,
    ) -> Result<AccessToken, OpenIdError> {
        let grant = self;
        let code = configuration
            .adapters()
            .code()
            .find(&grant.code)
            .await
            .ok_or_else(|| OpenIdError::invalid_grant("Authorization code not found"))?;

        validate_authorization_code(&code, &client)?;
        validate_redirect_uri(&grant, &code)?;
        validate_pkce(
            &grant,
            code.code_challenge.as_ref(),
            code.code_challenge_method,
        )?;

        let ttl = configuration.ttl();

        if configuration.issue_refresh_token(&client).await {
            let rt_ttl = ttl.refresh_token_ttl(&client).await;
            let refresh_token = RefreshTokenBuilder::default()
                .token(Uuid::new_v4())
                .client_id(code.client_id)
                .redirect_uri(code.redirect_uri)
                .subject(code.subject)
                .scope(code.scope)
                .state(code.state)
                .amr(code.amr)
                .acr(code.acr)
                .nonce(code.nonce)
                .expires_in(OffsetDateTime::now_utc() + rt_ttl)
                .created(OffsetDateTime::now_utc())
                .build()
                .map_err(|err| OpenIdError::server_error(err.into()))?;
        }

        // let access_token = AccessToken::bearer()
        todo!("sld")
    }
}

fn validate_authorization_code(
    code: &AuthorisationCode,
    client: &AuthenticatedClient,
) -> Result<(), OpenIdError> {
    if code.status != CodeStatus::Awaiting {
        return Err(OpenIdError::invalid_grant(
            "Authorization code already consumed",
        ));
    }
    if code.client_id != client.as_ref().id {
        return Err(OpenIdError::invalid_grant(
            "Client mismatch for authorization code",
        ));
    }
    if code.is_expired() {
        return Err(OpenIdError::invalid_grant("Authorization code is expired"));
    }
    Ok(())
}

fn validate_redirect_uri(
    grant: &AuthorisationCodeGrant,
    code: &AuthorisationCode,
) -> Result<(), OpenIdError> {
    if grant.redirect_uri != code.redirect_uri {
        return Err(OpenIdError::invalid_grant("Redirect uri mismatch"));
    }
    Ok(())
}

impl From<CodeChallengeError> for OpenIdError {
    fn from(err: CodeChallengeError) -> Self {
        error!("Error creating code challenge, {}", err);
        OpenIdError::invalid_request(err.to_string())
    }
}
