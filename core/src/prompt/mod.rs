use thiserror::Error;
use tracing::debug;
use url::Url;

use oidc_types::prompt::Prompt;
use oidc_types::response_mode::ResponseMode;
use oidc_types::state::State;

use crate::adapter::PersistenceError;
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
use crate::services::keystore::KeystoreService;
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

pub struct PromptSelector {
    prompt: Prompt,
    checks: Vec<(String, PromptCheck)>,
}

impl PromptSelector {
    pub fn new(prompt: Prompt, checks: Vec<(String, PromptCheck)>) -> Self {
        Self { prompt, checks }
    }

    pub fn prompt(&self) -> Prompt {
        self.prompt
    }

    pub async fn should_run(
        &self,
        provider: &OpenIDProviderConfiguration,
        keystore_service: &KeystoreService,
        user: Option<&AuthenticatedUser>,
        request: &ValidatedAuthorisationRequest,
        client: &ClientInformation,
    ) -> Result<bool, PromptError> {
        for (name, check) in &self.checks {
            let ctx = CheckContext {
                provider,
                keystore_service,
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
}

impl Default for PromptSelector {
    fn default() -> Self {
        PromptSelector {
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
