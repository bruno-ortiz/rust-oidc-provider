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
        interaction_url: Url,
    },
    Consent {
        id: Uuid,
        session: SessionID,
        request: ValidatedAuthorisationRequest,
        interaction_url: Url,
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
    pub fn login(
        session: SessionID,
        request: ValidatedAuthorisationRequest,
        interaction_url: Url,
    ) -> Self {
        let id = Uuid::new_v4();
        let url = Interaction::url(interaction_url, id);
        Self::Login {
            id,
            session,
            request,
            interaction_url: url,
        }
    }

    pub fn consent(
        session: SessionID,
        request: ValidatedAuthorisationRequest,
        user: AuthenticatedUser,
        interaction_url: Url,
    ) -> Self {
        let id = Uuid::new_v4();
        let url = Interaction::url(interaction_url, id);
        Self::Consent {
            id,
            session,
            request,
            user,
            interaction_url: url,
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

    fn url(mut interaction_url: Url, id: Uuid) -> Url {
        interaction_url
            .query_pairs_mut()
            .append_pair("interaction_id", id.to_string().as_str());
        interaction_url
    }

    pub fn uri(self) -> Url {
        match self {
            Interaction::Login {
                interaction_url, ..
            } => interaction_url,
            Interaction::Consent {
                interaction_url, ..
            } => interaction_url,
            Interaction::None { .. } => panic!("Should not be called when interaction is None"),
        }
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
