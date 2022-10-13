use async_trait::async_trait;
use thiserror::Error;

use oidc_types::prompt::Prompt;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::models::grant::Grant;
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

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

#[derive(Debug)]
pub struct LoginResolver;

#[async_trait]
impl PromptChecker for LoginResolver {
    async fn should_run(
        &self,
        user: Option<&AuthenticatedUser>,
        request: &ValidatedAuthorisationRequest,
    ) -> bool {
        if let Some(prompt) = request.prompt.as_ref() {
            if prompt.contains(&Prompt::Login) {
                return true;
            }
        }
        if let Some(_user) = user {
            //check acr
            //check max_age
            //check id_token_hint
            //check sub in id_token claim
            false
        } else {
            true
        }
    }
}

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

#[derive(Debug)]
pub struct ConsentResolver;

#[async_trait]
impl PromptChecker for ConsentResolver {
    async fn should_run(
        &self,
        user: Option<&AuthenticatedUser>,
        request: &ValidatedAuthorisationRequest,
    ) -> bool {
        if let Some(prompt) = request.prompt.as_ref() {
            if prompt.contains(&Prompt::Consent) {
                return true;
            }
        }
        if let Some(user) = user {
            let grant = if let Some(grant_id) = user.grant_id() {
                Grant::find(grant_id).await
            } else {
                None
            };
            if let Some(grant) = grant {
                grant.client_id() != request.client_id || grant.has_requested_scopes(&request.scope)
            } else {
                true
            }
        } else {
            true
        }
    }
}
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

#[derive(Debug)]
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

#[derive(Debug)]
pub enum PromptDispatcher {
    Login(LoginResolver),
    Consent(ConsentResolver),
    None(NoneResolver),
}

impl PromptDispatcher {
    pub fn default() -> [PromptDispatcher; 3] {
        [
            PromptDispatcher::Login(LoginResolver),
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
