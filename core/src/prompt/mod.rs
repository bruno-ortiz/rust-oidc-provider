use std::sync::Arc;

use thiserror::Error;
use tracing::info;
use url::Url;

use oidc_types::prompt::Prompt;
use oidc_types::response_mode::ResponseMode;
use oidc_types::state::State;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::named_check;
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

    pub async fn should_run(
        &self,
        user: Option<Arc<AuthenticatedUser>>,
        request: Arc<ValidatedAuthorisationRequest>,
    ) -> Result<bool, PromptError> {
        //check id_token_hint
        //check sub in id_token claim
        for (name, check) in &self.checks {
            let ctx = CheckContext {
                prompt: self.prompt,
                request: request.clone(),
                user: user.clone(),
            };
            if check(ctx).await? {
                info!(
                    "Prompt {} will be executed because of positive check: {}",
                    self.prompt, name
                );
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn resolve(
        &self,
        session: SessionID,
        user: Option<AuthenticatedUser>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<Interaction, PromptError> {
        match self.prompt {
            Prompt::Login => Ok(Interaction::login(session, request)),
            Prompt::Consent => {
                let user = user.ok_or_else(|| PromptError::login_required(&request))?;
                Ok(Interaction::consent(request, user))
            }
            Prompt::None => {
                let user = user.ok_or_else(|| PromptError::login_required(&request))?;
                Ok(Interaction::none(request, user))
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
