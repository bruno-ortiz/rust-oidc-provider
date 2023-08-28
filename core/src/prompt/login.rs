use async_trait::async_trait;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::prompt::{PromptError, PromptResolver};
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

pub struct LoginResolver;

#[async_trait]
impl PromptResolver for LoginResolver {
    async fn resolve(
        &self,
        session: SessionID,
        _user: Option<AuthenticatedUser>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<Interaction, PromptError> {
        Ok(Interaction::login(session, request))
    }
}
