use std::sync::Arc;

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::persistence::TransactionId;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

pub struct UserManager {
    provider: Arc<OpenIDProviderConfiguration>,
}

impl UserManager {
    pub fn new(provider: Arc<OpenIDProviderConfiguration>) -> Self {
        Self { provider }
    }

    pub async fn save(
        &self,
        user: AuthenticatedUser,
        txn: Option<TransactionId>,
    ) -> Result<AuthenticatedUser, PersistenceError> {
        self.provider.adapter().user().insert(user, txn).await
    }

    pub async fn update(
        &self,
        user: AuthenticatedUser,
        txn: Option<TransactionId>,
    ) -> Result<AuthenticatedUser, PersistenceError> {
        self.provider.adapter().user().update(user, txn).await
    }

    pub async fn find_by_session(
        &self,
        session: SessionID,
    ) -> Result<Option<AuthenticatedUser>, PersistenceError> {
        self.provider.adapter().user().find(&session).await
    }
}
