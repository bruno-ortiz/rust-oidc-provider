use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::models::grant::Grant;
use crate::prompt::{PromptError, PromptResolver};
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;
use async_trait::async_trait;

pub struct NoneResolver;

#[async_trait]
impl PromptResolver for NoneResolver {
    async fn resolve(
        &self,
        _session: SessionID,
        user: Option<AuthenticatedUser>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<Interaction, PromptError> {
        if let Some(user) = user {
            let grant = if let Some(grant_id) = user.grant_id() {
                Grant::find(grant_id).await
            } else {
                None
            };
            if grant.is_none() {
                return Err(PromptError::ConsentRequired(request));
            }
            Ok(Interaction::none(request, user))
        } else {
            Err(PromptError::LoginRequired(request))
        }
    }
}
