use itertools::Itertools;
use oidc_types::claims::ClaimOptions;
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
    _request: &ValidatedAuthorisationRequest,
) -> bool {
    let clock = OpenIDProviderConfiguration::clock();
    let max_age = user.max_age();
    let auth_limit = user.auth_time() + Duration::seconds(max_age as i64);
    clock.now() > auth_limit
}

pub(crate) fn check_acr_values(
    user: &AuthenticatedUser,
    request: &ValidatedAuthorisationRequest,
) -> bool {
    if let Some(claims) = &request.claims {
        match claims.id_token.get("acr") {
            None => false,
            Some(None) => false,
            Some(Some(claim_opts)) if skip_values_validation(claim_opts) => false,
            Some(Some(claim_opts)) => {
                let mut values = claim_opts
                    .values()
                    .expect("Should have claim values")
                    .iter()
                    .filter_map(|v| v.as_str());
                let provided_acr = user.acr();
                provided_acr.iter().any(|it| values.contains(&it))
            }
        }
    } else {
        false
    }
}

pub(crate) fn check_acr_value(
    user: &AuthenticatedUser,
    request: &ValidatedAuthorisationRequest,
) -> bool {
    if let Some(claims) = &request.claims {
        match claims.id_token.get("acr") {
            None => false,
            Some(None) => false,
            Some(Some(claim_opts)) if skip_value_validation(claim_opts) => false,
            Some(Some(claim_opts)) => {
                let value = claim_opts.value().expect("Should have claim value");
                let provided_acr = user.acr();
                provided_acr.iter().any(|it| value == it)
            }
        }
    } else {
        false
    }
}

fn skip_value_validation(claim_opts: &ClaimOptions) -> bool {
    !claim_opts.essential() || claim_opts.value().is_none()
}

fn skip_values_validation(claim_opts: &ClaimOptions) -> bool {
    !claim_opts.essential() || claim_opts.values().is_none()
}
