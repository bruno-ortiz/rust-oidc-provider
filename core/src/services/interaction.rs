use std::sync::Arc;

use url::Url;
use uuid::Uuid;

use oidc_types::subject::Subject;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::OpenIDProviderConfiguration;
use crate::services::authorisation::AuthorisationError;
pub use crate::services::types::Interaction;
use crate::session::SessionID;

pub struct InteractionService {
    configuration: Arc<OpenIDProviderConfiguration>,
}

impl InteractionService {
    pub fn new(configuration: Arc<OpenIDProviderConfiguration>) -> Self {
        Self { configuration }
    }

    pub async fn begin_interaction(
        &self,
        session: SessionID,
        request: ValidatedAuthorisationRequest,
    ) -> Result<Url, AuthorisationError> {
        let interaction_fn = self.configuration.interaction();
        let interaction = Interaction::login(session, request);
        let result: Url = interaction_fn(&interaction, &self.configuration);

        let repository = self.configuration.adapters().interaction();
        repository
            .save(interaction)
            .await
            .map_err(AuthorisationError::InteractionErr)?;
        Ok(result)
    }

    pub async fn complete_login(
        &self,
        interaction_id: Uuid,
        subject: Subject,
    ) -> Result<Url, AuthorisationError> {
        let repository = self.configuration.adapters().interaction();
        let interaction = repository.find(&interaction_id).await;
        todo!()
    }
}
