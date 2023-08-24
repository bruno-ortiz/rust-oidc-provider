use async_trait::async_trait;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::prompt::checks::{
    check_acr_value, check_acr_values, check_login_is_requested, check_max_age,
};
use crate::prompt::{PromptChecker, PromptError, PromptResolver};
use crate::services::types::Interaction;
use crate::session::SessionID;
use crate::user::AuthenticatedUser;

pub struct LoginResolver(Vec<fn(&AuthenticatedUser, &ValidatedAuthorisationRequest) -> bool>);

#[async_trait]
impl PromptChecker for LoginResolver {
    async fn should_run(
        &self,
        user: Option<&AuthenticatedUser>,
        request: &ValidatedAuthorisationRequest,
    ) -> bool {
        if let Some(user) = user {
            //check id_token_hint
            //check sub in id_token claim
            self.0.iter().any(|check| check(user, request))
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

impl Default for LoginResolver {
    fn default() -> Self {
        Self(vec![
            check_login_is_requested,
            check_max_age,
            check_acr_values,
            check_acr_value,
        ])
    }
}
