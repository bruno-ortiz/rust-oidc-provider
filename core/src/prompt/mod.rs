use thiserror::Error;
use tracing::debug;
use url::Url;
use uuid::Uuid;

use crate::adapter::PersistenceError;
use oidc_types::prompt::Prompt;
use oidc_types::response_mode::ResponseMode;
use oidc_types::state::State;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::OpenIDProviderConfiguration;
use crate::models::client::ClientInformation;
use crate::named_check;
use crate::pairwise::PairwiseError;
use crate::prompt::checks::{
    always_run, check_prompt_is_requested, check_user_must_be_authenticated,
    check_user_must_have_consented, CheckContext, PromptCheck,
};
use crate::prompt::PromptError::{ConsentRequired, LoginRequired};
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

pub mod checks;

#[derive(Debug, Error)]
pub enum PromptError {
    #[error("User is not authenticated")]
    LoginRequired {
        redirect_uri: Url,
        response_mode: ResponseMode,
        state: Option<State>,
    },
    #[error("User has not consented")]
    ConsentRequired {
        redirect_uri: Url,
        response_mode: ResponseMode,
        state: Option<State>,
    },
    #[error("Error resolving prompt pairwise subject: {}", .0)]
    Pairwise(#[from] PairwiseError),
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Internal(anyhow::Error),
}

impl PromptError {
    pub fn login_required(request: &ValidatedAuthorisationRequest) -> Self {
        LoginRequired {
            redirect_uri: request.redirect_uri.clone(),
            response_mode: request.response_type.default_response_mode(),
            state: request.state.clone(),
        }
    }

    pub fn consent_required(request: &ValidatedAuthorisationRequest) -> Self {
        ConsentRequired {
            redirect_uri: request.redirect_uri.clone(),
            response_mode: request.response_type.default_response_mode(),
            state: request.state.clone(),
        }
    }
}

pub struct PromptResolver {
    prompt: Prompt,
    checks: Vec<(String, PromptCheck)>,
}

impl PromptResolver {
    pub fn new(prompt: Prompt, checks: Vec<(String, PromptCheck)>) -> Self {
        Self { prompt, checks }
    }

    pub fn prompt(&self) -> Prompt {
        self.prompt
    }

    pub async fn should_run(
        &self,
        provider: &OpenIDProviderConfiguration,
        user: Option<&AuthenticatedUser>,
        request: &ValidatedAuthorisationRequest,
        client: &ClientInformation,
    ) -> Result<bool, PromptError> {
        for (name, check) in &self.checks {
            let ctx = CheckContext {
                provider,
                prompt: self.prompt,
                request,
                user,
                client,
            };
            if check(ctx).await? {
                debug!(
                    "Prompt {} will be executed because of positive check: {}",
                    self.prompt, name
                );
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub async fn resolve(
        &self,
        provider: &OpenIDProviderConfiguration,
        session: SessionID,
        user: Option<AuthenticatedUser>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<Interaction, PromptError> {
        match self.prompt {
            Prompt::Login => Ok(Interaction::login(session, request).save(provider).await?),
            Prompt::Consent => {
                let user = user.ok_or_else(|| PromptError::login_required(&request))?;
                let new_id = Uuid::new_v4();
                let user = user.with_interaction(new_id).update(provider).await?;
                let interaction = Interaction::consent_with_id(new_id, request, user)
                    .save(provider)
                    .await?;
                Ok(interaction)
            }
            Prompt::None => {
                let user = user.ok_or_else(|| PromptError::login_required(&request))?;
                let new_id = Uuid::new_v4();
                let user = user.with_interaction(new_id).update(provider).await?;
                let interaction = Interaction::none_with_id(new_id, request, user)
                    .save(provider)
                    .await?;
                Ok(interaction)
            }
            Prompt::SelectAccount => todo!("Not implemented"),
        }
    }
}

impl Default for PromptResolver {
    fn default() -> Self {
        PromptResolver {
            prompt: Prompt::None,
            checks: vec![
                named_check!(check_user_must_be_authenticated),
                named_check!(check_user_must_have_consented),
                named_check!(check_prompt_is_requested),
                named_check!(always_run),
            ],
        }
    }
}
