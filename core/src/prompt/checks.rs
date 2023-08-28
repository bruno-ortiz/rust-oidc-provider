use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use itertools::Itertools;
use time::Duration;

use oidc_types::claims::ClaimOptions;
use oidc_types::prompt::Prompt;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::user::AuthenticatedUser;

pub type PromptCheck =
    Box<dyn Fn(CheckContext) -> Pin<Box<dyn Future<Output = bool> + Send + Sync>> + Send + Sync>;

pub struct CheckContext {
    pub prompt: Prompt,
    pub user: Option<Arc<AuthenticatedUser>>,
    pub request: Arc<ValidatedAuthorisationRequest>,
}

pub fn boxed_check<N, F>(
    check_name: N,
    f: impl Fn(CheckContext) -> F + Send + Sync + 'static,
) -> (String, PromptCheck)
where
    F: Future<Output = bool> + Send + Sync + 'static,
    N: Into<String>,
{
    (check_name.into(), Box::new(move |ctx| Box::pin(f(ctx))))
}

pub async fn check_prompt_is_requested(
    CheckContext {
        prompt, request, ..
    }: CheckContext,
) -> bool {
    if let Some(requested_prompt) = request.prompt.as_ref() {
        requested_prompt.contains(&prompt)
    } else {
        false
    }
}

pub async fn check_user_is_authenticated(CheckContext { user, .. }: CheckContext) -> bool {
    user.is_none()
}

pub async fn check_max_age(CheckContext { user, .. }: CheckContext) -> bool {
    let clock = OpenIDProviderConfiguration::clock();
    let user = user.expect("Expected authenticated user");
    let max_age = user.max_age();
    let auth_limit = user.auth_time() + Duration::seconds(max_age as i64);
    clock.now() > auth_limit
}

pub async fn check_acr_values(CheckContext { request, user, .. }: CheckContext) -> bool {
    let user = user.expect("Expected authenticated user");
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
                !provided_acr.iter().any(|it| values.contains(&it.as_str()))
            }
        }
    } else {
        false
    }
}

pub async fn check_acr_value(CheckContext { request, user, .. }: CheckContext) -> bool {
    let user = user.expect("Expected authenticated user");
    if let Some(claims) = &request.claims {
        match claims.id_token.get("acr") {
            None => false,
            Some(None) => false,
            Some(Some(claim_opts)) if skip_value_validation(claim_opts) => false,
            Some(Some(claim_opts)) => {
                let value = claim_opts.value().expect("Should have claim value");
                let provided_acr = user.acr();
                !provided_acr.iter().any(|it| value == it)
            }
        }
    } else {
        false
    }
}

fn skip_value_validation(claim_opts: &ClaimOptions) -> bool {
    !claim_opts.is_essential() || claim_opts.value().is_none()
}

fn skip_values_validation(claim_opts: &ClaimOptions) -> bool {
    !claim_opts.is_essential() || claim_opts.values().is_none()
}

#[macro_export]
macro_rules! named_check {
    ($func:path) => {
        $crate::prompt::checks::boxed_check(stringify!($func), $func)
    };
}
