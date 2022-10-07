use url::Url;
use uuid::Uuid;

use oidc_types::identifiable::Identifiable;

use crate::adapter::PersistenceError;
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

    pub fn consent(request: ValidatedAuthorisationRequest, user: AuthenticatedUser) -> Self {
        Self::Consent {
            id: user.interaction_id(),
            session: user.session(),
            request,
            user,
        }
    }

    pub fn none(request: ValidatedAuthorisationRequest, user: AuthenticatedUser) -> Self {
        Self::None {
            id: user.interaction_id(),
            session: user.session(),
            request,
            user,
        }
    }

    pub fn uri(self) -> Url {
        let id = self.id();
        let config = OpenIDProviderConfiguration::instance();
        let mut url = config.interaction_url_resolver()(self);
        Self::add_id(&mut url, id);
        url
    }

    pub fn consume_authenticated(
        self,
    ) -> Option<(AuthenticatedUser, ValidatedAuthorisationRequest)> {
        match self {
            Interaction::Login { .. } => None,
            Interaction::Consent { user, request, .. } => Some((user, request)),
            Interaction::None { user, request, .. } => Some((user, request)),
        }
    }

    fn add_id(url: &mut Url, id: Uuid) {
        url.query_pairs_mut()
            .append_pair("interaction_id", id.to_string().as_str());
    }

    pub async fn save(self) -> Result<Self, PersistenceError> {
        let config = OpenIDProviderConfiguration::instance();
        config.adapters().interaction().save(self).await
    }

    pub async fn find(id: Uuid) -> Option<Interaction> {
        let configuration = OpenIDProviderConfiguration::instance();
        configuration.adapters().interaction().find(&id).await
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
