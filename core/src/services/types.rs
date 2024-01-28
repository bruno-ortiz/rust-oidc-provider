use time::OffsetDateTime;
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
        created: OffsetDateTime,
    },
    Consent {
        id: Uuid,
        session: SessionID,
        request: ValidatedAuthorisationRequest,
        user: AuthenticatedUser,
        created: OffsetDateTime,
    },
    None {
        id: Uuid,
        session: SessionID,
        request: ValidatedAuthorisationRequest,
        user: AuthenticatedUser,
        created: OffsetDateTime,
    },
}

impl Interaction {
    pub fn login(session: SessionID, request: ValidatedAuthorisationRequest) -> Self {
        let id = Uuid::new_v4();
        Self::login_with_id(id, session, request)
    }

    pub fn login_with_id(
        id: Uuid,
        session: SessionID,
        request: ValidatedAuthorisationRequest,
    ) -> Self {
        Self::Login {
            id,
            session,
            request,
            created: OffsetDateTime::now_utc(),
        }
    }

    pub fn consent(request: ValidatedAuthorisationRequest, user: AuthenticatedUser) -> Self {
        Self::consent_with_id(Uuid::new_v4(), request, user)
    }

    pub fn consent_with_id(
        id: Uuid,
        request: ValidatedAuthorisationRequest,
        user: AuthenticatedUser,
    ) -> Self {
        Self::Consent {
            id,
            session: user.session(),
            request,
            user,
            created: OffsetDateTime::now_utc(),
        }
    }

    pub fn none(request: ValidatedAuthorisationRequest, user: AuthenticatedUser) -> Self {
        Self::none_with_id(Uuid::new_v4(), request, user)
    }

    pub fn none_with_id(
        id: Uuid,
        request: ValidatedAuthorisationRequest,
        user: AuthenticatedUser,
    ) -> Self {
        Self::None {
            id,
            session: user.session(),
            request,
            user,
            created: OffsetDateTime::now_utc(),
        }
    }

    pub fn uri(self) -> Url {
        let id = *self.id();
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
        config.adapter().interaction(None).insert(self).await
    }

    pub async fn update(self) -> Result<Self, PersistenceError> {
        let config = OpenIDProviderConfiguration::instance();
        config.adapter().interaction(None).update(self).await
    }

    pub async fn find(id: Uuid) -> Result<Option<Interaction>, PersistenceError> {
        let configuration = OpenIDProviderConfiguration::instance();
        configuration.adapter().interaction(None).find(&id).await
    }
}

impl Identifiable<Uuid> for Interaction {
    fn id(&self) -> &Uuid {
        match *self {
            Interaction::Login { ref id, .. } => id,
            Interaction::Consent { ref id, .. } => id,
            Interaction::None { ref id, .. } => id,
        }
    }
}
