use crate::configuration::OpenIDProviderConfiguration;
use crate::session::SessionID;
use oidc_types::identifiable::Identifiable;
use oidc_types::subject::Subject;
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    session: SessionID,
    subject: Subject,
    auth_time: OffsetDateTime,
    max_age: u64,
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
