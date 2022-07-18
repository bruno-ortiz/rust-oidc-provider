use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::session::SessionID;
use oidc_types::grant::Grant;
use oidc_types::identifiable::Identifiable;
use oidc_types::subject::Subject;
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    session: SessionID,
    subject: Subject,
    auth_time: OffsetDateTime,
    max_age: u64,
    grant: Option<Grant>,
}

impl AuthenticatedUser {
    pub fn new(
        session: SessionID,
        subject: Subject,
        auth_time: OffsetDateTime,
        max_age: u64,
    ) -> Self {
        Self {
            session,
            subject,
            auth_time,
            max_age,
            grant: None,
        }
    }

    pub fn sub(&self) -> &Subject {
        &self.subject
    }
    pub fn session(&self) -> SessionID {
        self.session
    }
    pub fn auth_time(&self) -> OffsetDateTime {
        self.auth_time
    }
    pub fn max_age(&self) -> u64 {
        self.max_age
    }

    pub fn has_requested_grant(&self, requested: Grant) -> bool {
        if let Some(ref grant) = self.grant {
            *grant == requested
        } else {
            false
        }
    }

    pub fn with_grant(mut self, grant: Grant) -> Self {
        self.grant = Some(grant);
        self
    }

    pub async fn save(
        self,
        config: &OpenIDProviderConfiguration,
    ) -> Result<Self, PersistenceError> {
        config.adapters().user().save(self).await
    }
}

impl Identifiable<String> for AuthenticatedUser {
    fn id(&self) -> String {
        self.session.to_string()
    }
}

pub async fn find_user_by_session(
    config: &OpenIDProviderConfiguration,
    session: SessionID,
) -> Option<AuthenticatedUser> {
    config.adapters().user().find(&session.to_string()).await
}
