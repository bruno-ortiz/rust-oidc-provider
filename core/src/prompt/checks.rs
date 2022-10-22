use time::Duration;

use oidc_types::prompt::Prompt;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::user::AuthenticatedUser;

pub(crate) fn check_login_is_requested(
    _user: &AuthenticatedUser,
    request: &ValidatedAuthorisationRequest,
) -> bool {
    if let Some(prompt) = request.prompt.as_ref() {
        prompt.contains(&Prompt::Login)
    } else {
        false
    }
}

pub(crate) fn check_max_age(
    user: &AuthenticatedUser,
    request: &ValidatedAuthorisationRequest,
) -> bool {
    if let Some(ref max_age) = request.max_age {
        let clock = OpenIDProviderConfiguration::clock();
        let auth_limit = user.auth_time() + Duration::seconds(*max_age as i64);
        let now = clock.now();
        now > auth_limit
    } else {
        false
    }
}
