use crate::adapter::PersistenceError;
use oidc_types::identifiable::Identifiable;
use url::Url;
use uuid::Uuid;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::OpenIDProviderConfiguration;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

#[derive(Debug, Clone)]
pub enum Interaction {
    Login {
        id: Uuid,
        session: SessionID,
        request: ValidatedAuthorisationRequest,
    },
    Consent {
        id: Uuid,
        session: SessionID,
        request: ValidatedAuthorisationRequest,
        user: AuthenticatedUser,
    },
    None {
        id: Uuid,
        session: SessionID,
        request: ValidatedAuthorisationRequest,
        user: AuthenticatedUser,
    },
}

impl Interaction {
    pub fn login(session: SessionID, request: ValidatedAuthorisationRequest) -> Self {
        let id = Uuid::new_v4();
        Self::Login {
            id,
            session,
            request,
        }
    }

    pub fn consent(
        session: SessionID,
        request: ValidatedAuthorisationRequest,
        user: AuthenticatedUser,
    ) -> Self {
        let id = Uuid::new_v4();
        Self::Consent {
            id,
            session,
            request,
            user,
        }
    }

    pub fn none(
        session: SessionID,
        request: ValidatedAuthorisationRequest,
        user: AuthenticatedUser,
    ) -> Self {
        Self::None {
            id: Uuid::new_v4(),
            session,
            request,
            user,
        }
    }

    pub fn uri(self, config: &OpenIDProviderConfiguration) -> Url {
        let id = self.id();
        let mut url = config.interaction_url_resolver()(self, config);
        Self::add_id(&mut url, id);
        url
    }

    fn add_id(url: &mut Url, id: Uuid) {
        url.query_pairs_mut()
            .append_pair("interaction_id", id.to_string().as_str());
    }

    pub async fn save(
        self,
        config: &OpenIDProviderConfiguration,
    ) -> Result<Self, PersistenceError> {
        config.adapters().interaction().save(self).await
    }

    pub async fn find(config: &OpenIDProviderConfiguration, id: Uuid) -> Option<Interaction> {
        config.adapters().interaction().find(&id).await
    }
}

impl Identifiable<Uuid> for Interaction {
    fn id(&self) -> Uuid {
        match *self {
            Interaction::Login { id, .. } => id,
            Interaction::Consent { id, .. } => id,
            Interaction::None { id, .. } => id,
        }
    }
}
