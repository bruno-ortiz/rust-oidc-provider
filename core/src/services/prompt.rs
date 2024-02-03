use std::sync::Arc;

use derive_new::new;

use oidc_types::prompt::Prompt;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::OpenIDProviderConfiguration;
use crate::manager::interaction_manager::InteractionManager;
use crate::models::client::ClientInformation;
use crate::prompt::PromptError;
use crate::user::AuthenticatedUser;

#[derive(new)]
pub struct PromptService {
    provider: Arc<OpenIDProviderConfiguration>,
}

impl PromptService {
    pub async fn resolve_prompt(
        &self,
        request: &ValidatedAuthorisationRequest,
        user: Option<&AuthenticatedUser>,
        client: &ClientInformation,
    ) -> Result<Option<Prompt>, PromptError> {
        let mut prompt: Option<Prompt> = None;
        if let Some(requested_prompt) = &request.prompt {
            prompt = self
                .provider
                .prompts()
                .iter()
                .find(|&p| requested_prompt.contains(&p.prompt()))
                .map(|selector| selector.prompt());
        } else {
            let prompt_checks = self.provider.prompts();
            for selector in prompt_checks {
                if selector
                    .should_run(&self.provider, user, request, client)
                    .await?
                {
                    prompt = Some(selector.prompt());
                    break;
                }
            }
        }
        Ok(prompt)
    }
}
