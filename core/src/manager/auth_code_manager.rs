use std::sync::Arc;

use oidc_types::code::Code;
use oidc_types::pkce::validate_pkce;
use oidc_types::token_request::AuthorisationCodeGrant;

use crate::adapter::PersistenceError;
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::authorisation_code::AuthorisationCode;
use crate::models::Status;
use crate::persistence::TransactionId;

pub struct AuthorisationCodeManager {
    provider: Arc<OpenIDProviderConfiguration>,
}

impl AuthorisationCodeManager {
    pub fn new(provider: Arc<OpenIDProviderConfiguration>) -> Self {
        Self { provider }
    }

    pub async fn find(&self, code: &Code) -> Result<Option<AuthorisationCode>, PersistenceError> {
        self.provider.adapter().code().find(code).await
    }

    pub async fn save(
        &self,
        auth_code: AuthorisationCode,
        txn: Option<TransactionId>,
    ) -> Result<AuthorisationCode, PersistenceError> {
        self.provider.adapter().code().insert(auth_code, txn).await
    }

    pub async fn consume(
        &self,
        mut auth_code: AuthorisationCode,
        txn: Option<TransactionId>,
    ) -> Result<AuthorisationCode, OpenIdError> {
        auth_code.status = Status::Consumed;
        self.provider
            .adapter()
            .code()
            .update(auth_code, txn)
            .await
            .map_err(OpenIdError::server_error)
    }

    pub fn is_expired(&self, auth_code: &AuthorisationCode) -> bool {
        let now = self.provider.clock_provider().now();
        auth_code.expires_in <= now
    }

    pub fn validate(
        &self,
        grant: &AuthorisationCodeGrant,
        auth_code: &AuthorisationCode,
    ) -> Result<(), OpenIdError> {
        if self.is_expired(auth_code) {
            return Err(OpenIdError::invalid_grant("Authorization code is expired"));
        }
        validate_pkce(
            grant,
            auth_code.code_challenge.as_ref(),
            auth_code.code_challenge_method,
        )?;
        Ok(())
    }
}
