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
use crate::models::grant::Grant;
use crate::prompt::PromptError;
use crate::user::AuthenticatedUser;

pub type PromptCheck = Box<
    dyn Fn(CheckContext) -> Pin<Box<dyn Future<Output = Result<bool, PromptError>> + Send>>
        + Send
        + Sync,
>;

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
    F: Future<Output = Result<bool, PromptError>> + Send + 'static,
    N: Into<String>,
{
    (check_name.into(), Box::new(move |ctx| Box::pin(f(ctx))))
}

pub async fn check_prompt_is_requested(
    CheckContext {
        prompt, request, ..
    }: CheckContext,
) -> Result<bool, PromptError> {
    if let Some(requested_prompt) = request.prompt.as_ref() {
        Ok(requested_prompt.contains(&prompt))
    } else {
        Ok(false)
    }
}

pub async fn check_user_is_authenticated(
    CheckContext { user, .. }: CheckContext,
) -> Result<bool, PromptError> {
    Ok(user.is_none())
}

pub async fn always_run(CheckContext { .. }: CheckContext) -> Result<bool, PromptError> {
    Ok(true)
}

pub async fn check_user_must_be_authenticated(
    CheckContext { user, request, .. }: CheckContext,
) -> Result<bool, PromptError> {
    if user.is_none() {
        Err(PromptError::login_required(&request))
    } else {
        Ok(false)
    }
}

pub async fn check_user_has_consented(
    CheckContext { user, request, .. }: CheckContext,
) -> Result<bool, PromptError> {
    let user = user.ok_or(PromptError::login_required(&request))?;
    let grant = if let Some(grant_id) = user.grant_id() {
        Grant::find(grant_id).await
    } else {
        None
    };
    if let Some(grant) = grant {
        Ok(grant.client_id() != request.client_id || !grant.has_requested_scopes(&request.scope))
    } else {
        Ok(true)
    }
}

pub async fn check_user_must_have_consented(
    CheckContext { user, request, .. }: CheckContext,
) -> Result<bool, PromptError> {
    let user = user.ok_or(PromptError::login_required(&request))?;
    let grant = if let Some(grant_id) = user.grant_id() {
        Grant::find(grant_id).await
    } else {
        None
    };
    if grant.is_none() {
        Err(PromptError::consent_required(&request))
    } else {
        Ok(false)
    }
}

pub async fn check_max_age(
    CheckContext { user, request, .. }: CheckContext,
) -> Result<bool, PromptError> {
    let clock = OpenIDProviderConfiguration::clock();
    let user = user.ok_or(PromptError::login_required(&request))?;
    let max_age = user.max_age();
    let auth_limit = user.auth_time() + Duration::seconds(max_age as i64);
    Ok(clock.now() > auth_limit)
}

pub async fn check_acr_values(
    CheckContext { request, user, .. }: CheckContext,
) -> Result<bool, PromptError> {
    let user = user.ok_or(PromptError::login_required(&request))?;
    if let Some(claims) = &request.claims {
        match claims.id_token.get("acr") {
            None => Ok(false),
            Some(None) => Ok(false),
            Some(Some(claim_opts)) if skip_values_validation(claim_opts) => Ok(false),
            Some(Some(claim_opts)) => {
                let mut values = claim_opts
                    .values()
                    .expect("Should have claim values")
                    .iter()
                    .filter_map(|v| v.as_str());
                let provided_acr = user.acr();
                Ok(!provided_acr.iter().any(|it| values.contains(&it.as_str())))
            }
        }
    } else {
        Ok(false)
    }
}

pub async fn check_acr_value(
    CheckContext { request, user, .. }: CheckContext,
) -> Result<bool, PromptError> {
    let user = user.ok_or(PromptError::login_required(&request))?;
    if let Some(claims) = &request.claims {
        match claims.id_token.get("acr") {
            None => Ok(false),
            Some(None) => Ok(false),
            Some(Some(claim_opts)) if skip_value_validation(claim_opts) => Ok(false),
            Some(Some(claim_opts)) => {
                let value = claim_opts.value().expect("Should have claim value");
                let provided_acr = user.acr();
                Ok(!provided_acr.iter().any(|it| value == it))
            }
        }
    } else {
        Ok(false)
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
