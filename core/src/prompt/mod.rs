use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;
use tracing::info;

use oidc_types::prompt::Prompt;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::named_check;
use crate::prompt::checks::{check_prompt_is_requested, CheckContext, PromptCheck};
use crate::prompt::none::NoneResolver;
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

pub mod checks;
pub mod consent;
pub mod login;
pub mod none;

#[derive(Debug, Error)]
pub enum PromptError {
    #[error("User is not authenticated")]
    LoginRequired(ValidatedAuthorisationRequest),
    #[error("User has not consented")]
    ConsentRequired(ValidatedAuthorisationRequest),
}
#[async_trait]
pub trait PromptResolver {
    async fn resolve(
        &self,
        session: SessionID,
        user: Option<AuthenticatedUser>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<Interaction, PromptError>;
}

pub struct PromptImpl {
    prompt: Prompt,
    checks: Vec<(String, PromptCheck)>,
    resolver: Box<dyn PromptResolver + Send + Sync>,
}

impl PromptImpl {
    pub fn new(
        prompt: Prompt,
        checks: Vec<(String, PromptCheck)>,
        resolver: Box<dyn PromptResolver + Send + Sync>,
    ) -> Self {
        Self {
            prompt,
            checks,
            resolver,
        }
    }

    pub async fn should_run(
        &self,
        user: Option<Arc<AuthenticatedUser>>,
        request: Arc<ValidatedAuthorisationRequest>,
    ) -> bool {
        //check id_token_hint
        //check sub in id_token claim
        for (name, check) in &self.checks {
            let ctx = CheckContext {
                prompt: self.prompt,
                request: request.clone(),
                user: user.clone(),
            };
            if check(ctx).await {
                info!(
                    "Prompt {} will be executed because of positive check: {}",
                    self.prompt, name
                );
                return true;
            }
        }
        false
    }
    pub async fn resolve(
        &self,
        session: SessionID,
        user: Option<AuthenticatedUser>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<Interaction, PromptError> {
        self.resolver.resolve(session, user, request).await
    }
}

impl Default for PromptImpl {
    fn default() -> Self {
        PromptImpl {
            prompt: Prompt::None,
            checks: vec![named_check!(check_prompt_is_requested)],
            resolver: Box::new(NoneResolver),
        }
    }
}
