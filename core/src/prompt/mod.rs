use async_trait::async_trait;
use thiserror::Error;

use oidc_types::prompt::Prompt;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::prompt::consent::ConsentResolver;
use crate::prompt::login::LoginResolver;
use crate::prompt::none::NoneResolver;
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

mod checks;
mod consent;
mod login;
pub(crate) mod none;

#[derive(Debug, Error)]
pub enum PromptError {
    #[error("User is not authenticated")]
    LoginRequired(ValidatedAuthorisationRequest),
    #[error("User has not consented")]
    ConsentRequired(ValidatedAuthorisationRequest),
}

#[async_trait]
pub trait PromptChecker: PromptResolver {
    async fn should_run(
        &self,
        user: Option<&AuthenticatedUser>,
        request: &ValidatedAuthorisationRequest,
    ) -> bool;
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

pub enum PromptDispatcher {
    Login(LoginResolver),
    Consent(ConsentResolver),
    None(NoneResolver),
}

impl PromptDispatcher {
    pub fn default() -> [PromptDispatcher; 3] {
        [
            PromptDispatcher::Login(LoginResolver::default()),
            PromptDispatcher::Consent(ConsentResolver),
            PromptDispatcher::None(NoneResolver),
        ]
    }
}

#[async_trait]
impl PromptResolver for PromptDispatcher {
    async fn resolve(
        &self,
        session: SessionID,
        user: Option<AuthenticatedUser>,
        request: ValidatedAuthorisationRequest,
    ) -> Result<Interaction, PromptError> {
        match self {
            PromptDispatcher::Login(inner) => inner.resolve(session, user, request).await,
            PromptDispatcher::Consent(inner) => inner.resolve(session, user, request).await,
            PromptDispatcher::None(inner) => inner.resolve(session, user, request).await,
        }
    }
}

#[async_trait]
impl PromptChecker for PromptDispatcher {
    async fn should_run(
        &self,
        user: Option<&AuthenticatedUser>,
        request: &ValidatedAuthorisationRequest,
    ) -> bool {
        let none_requested = request
            .prompt
            .as_ref()
            .map(|it| it.contains(&Prompt::None))
            .unwrap_or(false);
        match self {
            PromptDispatcher::Login(inner) if !none_requested => {
                inner.should_run(user, request).await
            }
            PromptDispatcher::Consent(inner) if !none_requested => {
                inner.should_run(user, request).await
            }
            PromptDispatcher::None(_) => true,
            _ => false,
        }
    }
}
