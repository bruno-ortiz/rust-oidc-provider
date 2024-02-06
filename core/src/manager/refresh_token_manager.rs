use std::sync::Arc;

use uuid::Uuid;

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::refresh_token::RefreshToken;
use crate::models::Status;
use crate::persistence::TransactionId;

pub struct RefreshTokenManager {
    provider: Arc<OpenIDProviderConfiguration>,
}

impl RefreshTokenManager {
    pub fn new(provider: Arc<OpenIDProviderConfiguration>) -> Self {
        Self { provider }
    }

    pub async fn find(&self, id: Uuid) -> Result<Option<RefreshToken>, PersistenceError> {
        self.provider.adapter().refresh().find(&id).await
    }

    pub async fn save(
        &self,
        refresh_token: RefreshToken,
        txn: Option<TransactionId>,
    ) -> Result<RefreshToken, PersistenceError> {
        self.provider
            .adapter()
            .refresh()
            .insert(refresh_token, txn)
            .await
    }

    pub async fn consume(
        &self,
        mut refresh_token: RefreshToken,
        txn: Option<TransactionId>,
    ) -> Result<RefreshToken, OpenIdError> {
        refresh_token.status = Status::Consumed;
        self.provider
            .adapter()
            .refresh()
            .update(refresh_token, txn)
            .await
            .map_err(OpenIdError::server_error)
    }

    pub fn validate(&self, refresh_token: &RefreshToken) -> Result<(), OpenIdError> {
        if refresh_token.status == Status::Consumed {
            return Err(OpenIdError::invalid_grant("Refresh token already used"));
        }
        if refresh_token.is_expired(self.provider.clock_provider()) {
            return Err(OpenIdError::invalid_grant("Refresh token is expired"));
        }
        Ok(())
    }
}
