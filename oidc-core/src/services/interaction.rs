use std::sync::Arc;

use url::Url;
use uuid::Uuid;

use oidc_types::subject::Subject;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::OpenIDProviderConfiguration;
use crate::response_mode::encoder::DynamicResponseModeEncoder;
use crate::response_type::resolver::DynamicResponseTypeResolver;
use crate::services::authorisation::{AuthorisationError, AuthorisationService};
pub use crate::services::types::Interaction;
use crate::session::SessionID;

pub struct InteractionService {
    configuration: Arc<OpenIDProviderConfiguration>,
    auth_service:
        Arc<AuthorisationService<DynamicResponseTypeResolver, DynamicResponseModeEncoder>>,
}

impl InteractionService {
    pub fn new(
        configuration: Arc<OpenIDProviderConfiguration>,
        auth_service: Arc<
            AuthorisationService<DynamicResponseTypeResolver, DynamicResponseModeEncoder>,
        >,
    ) -> Self {
        Self {
            configuration,
            auth_service,
        }
    }
}

impl InteractionService {
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

    pub fn complete_login(
        &self,
        interaction_id: Uuid,
        subject: Subject,
    ) -> Result<Url, AuthorisationError> {
        let repository = self.configuration.adapters().interaction();
        let interaction = repository.find(&interaction_id);
        todo!()
    }
}
