use async_trait::async_trait;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::prompt::{PromptError, PromptResolver};
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

pub struct ConsentResolver;

// #[async_trait]
// impl PromptChecker for ConsentResolver {
//     async fn should_run(
//         &self,
//         user: Option<&AuthenticatedUser>,
//         request: &ValidatedAuthorisationRequest,
//     ) -> bool {
//         if let Some(prompt) = request.prompt.as_ref() {
//             if prompt.contains(&Prompt::Consent) {
//                 return true;
//             }
//         }
//         if let Some(user) = user {
//             let grant = if let Some(grant_id) = user.grant_id() {
//                 Grant::find(grant_id).await
//             } else {
//                 None
//             };
//             if let Some(grant) = grant {
//                 grant.client_id() != request.client_id || grant.has_requested_scopes(&request.scope)
//             } else {
//                 true
//             }
//         } else {
//             true
//         }
//     }
// }
#[async_trait]
impl PromptResolver for ConsentResolver {
    async fn resolve(
        &self,
        _session: SessionID,
        user: Option<AuthenticatedUser>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<Interaction, PromptError> {
        if let Some(user) = user {
            Ok(Interaction::consent(request, user))
        } else {
            Err(PromptError::LoginRequired(request))
        }
    }
}
