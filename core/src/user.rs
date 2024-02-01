use time::OffsetDateTime;
use uuid::Uuid;

use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::identifiable::Identifiable;
use oidc_types::subject::Subject;

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::models::grant::GrantID;
use crate::session::SessionID;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    session: SessionID,
    subject: Subject,
    auth_time: OffsetDateTime,
    grant_id: Option<GrantID>,
    interaction_id: Uuid,
    acr: Acr,
    amr: Option<Amr>,
}

impl AuthenticatedUser {
    pub fn new(
        session: SessionID,
        subject: Subject,
        auth_time: OffsetDateTime,
        interaction_id: Uuid,
        acr: Option<Acr>,
        amr: Option<Amr>,
    ) -> Self {
        Self {
            session,
            subject,
            auth_time,
            interaction_id,
            amr,
            acr: acr.unwrap_or_default(),
            grant_id: None,
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
    pub fn acr(&self) -> &Acr {
        &self.acr
    }
    pub fn amr(&self) -> Option<&Amr> {
        self.amr.as_ref()
    }
    pub fn interaction_id(&self) -> Uuid {
        self.interaction_id
    }

    pub fn grant_id(&self) -> Option<GrantID> {
        self.grant_id
    }

    pub fn with_grant(mut self, grant: GrantID) -> Self {
        self.grant_id = Some(grant);
        self
    }
    pub fn with_interaction(mut self, interaction_id: Uuid) -> Self {
        self.interaction_id = interaction_id;
        self
    }

    pub async fn save(
        self,
        provider: &OpenIDProviderConfiguration,
    ) -> Result<Self, PersistenceError> {
        provider.adapter().user().insert(self, None).await
    }

    pub async fn update(
        self,
        provider: &OpenIDProviderConfiguration,
    ) -> Result<Self, PersistenceError> {
        provider.adapter().user().update(self, None).await
    }

    pub async fn find_by_session(
        provider: &OpenIDProviderConfiguration,
        session: SessionID,
    ) -> Result<Option<AuthenticatedUser>, PersistenceError> {
        provider.adapter().user().find(&session).await
    }
}

impl Identifiable<SessionID> for AuthenticatedUser {
    fn id(&self) -> &SessionID {
        &self.session
    }
}
