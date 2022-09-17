use time::OffsetDateTime;

use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::grant::Grant;
use oidc_types::identifiable::Identifiable;
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::session::SessionID;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    session: SessionID,
    subject: Subject,
    auth_time: OffsetDateTime,
    max_age: u64,
    grant: Option<Grant>,
    acr: Acr,
    amr: Option<Amr>,
}

impl AuthenticatedUser {
    pub fn new(
        session: SessionID,
        subject: Subject,
        auth_time: OffsetDateTime,
        max_age: u64,
        acr: Option<Acr>,
        amr: Option<Amr>,
    ) -> Self {
        Self {
            session,
            subject,
            auth_time,
            max_age,
            amr,
            acr: acr.unwrap_or_default(),
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
    pub fn acr(&self) -> &Acr {
        &self.acr
    }
    pub fn amr(&self) -> Option<&Amr> {
        self.amr.as_ref()
    }

    pub fn grant(&self) -> Option<&Grant> {
        self.grant.as_ref() //TODO: create a GrantedUser?
    }

    pub fn has_requested_grant(&self, requested: &Scopes) -> bool {
        if let Some(ref grant) = self.grant {
            grant.scopes().contains_all(requested)
        } else {
            false
        }
    }

    pub fn with_grant(mut self, grant: Grant) -> Self {
        self.grant = Some(grant);
        self
    }

    pub async fn save(self) -> Result<Self, PersistenceError> {
        let configuration = OpenIDProviderConfiguration::instance();
        configuration.adapters().user().save(self).await
    }
}

impl Identifiable<String> for AuthenticatedUser {
    fn id(&self) -> String {
        self.session.to_string()
    }
}

pub async fn find_user_by_session(session: SessionID) -> Option<AuthenticatedUser> {
    let config = OpenIDProviderConfiguration::instance();
    config.adapters().user().find(&session.to_string()).await
}
