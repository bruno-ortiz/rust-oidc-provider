use oidc_types::identifiable::Identifiable;
use uuid::Uuid;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::session::{AuthenticatedUser, SessionID};

#[derive(Debug, Clone)]
pub enum InteractionStatus {
    Login,
    Consent,
    Rejected,
    Completed,
}

#[derive(Debug, Clone)]
pub struct Interaction {
    id: Uuid,
    session: SessionID,
    request: ValidatedAuthorisationRequest,
    status: InteractionStatus,
    user: Option<AuthenticatedUser>,
}

impl Interaction {
    pub fn login(session: SessionID, request: ValidatedAuthorisationRequest) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            session,
            request,
            status: InteractionStatus::Login,
            user: None,
        }
    }

    pub fn id(&self) -> &Uuid {
        &self.id
    }
    pub fn user(&self) -> &Option<AuthenticatedUser> {
        &self.user
    }
}

impl Identifiable<Uuid> for Interaction {
    fn id(&self) -> Uuid {
        self.id
    }
}
