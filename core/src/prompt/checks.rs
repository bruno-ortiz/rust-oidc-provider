use std::future::Future;
use std::pin::Pin;

use itertools::Itertools;
use serde_json::Value;
use time::Duration;

use oidc_types::claims::ClaimOptions;
use oidc_types::jose::jwt2::JWT;
use oidc_types::prompt::Prompt;
use oidc_types::subject_type::SubjectType;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::models::client::ClientInformation;
use crate::models::grant::Grant;
use crate::prompt::PromptError;
use crate::user::AuthenticatedUser;
use crate::utils::resolve_sub;

pub type PromptCheck = Box<
    dyn Fn(CheckContext<'_>) -> Pin<Box<dyn Future<Output = Result<bool, PromptError>> + Send + '_>>
        + Send
        + Sync,
>;

pub struct CheckContext<'a> {
    pub config: &'a OpenIDProviderConfiguration,
    pub prompt: Prompt,
    pub user: Option<&'a AuthenticatedUser>,
    pub request: &'a ValidatedAuthorisationRequest,
    pub client: &'a ClientInformation,
}

pub trait CheckFn<'a> {
    type Output: Future<Output = Result<bool, PromptError>> + Send + 'a;
    fn call(&self, ctx: CheckContext<'a>) -> Self::Output;
}

impl<'a, F, R> CheckFn<'a> for F
where
    F: Fn(CheckContext<'a>) -> R,
    R: Future<Output = Result<bool, PromptError>> + Send + 'a,
{
    type Output = R;
    fn call(&self, ctx: CheckContext<'a>) -> R {
        self(ctx)
    }
}
pub fn boxed_check<N, F>(check_name: N, f: F) -> (String, PromptCheck)
where
    F: for<'a> CheckFn<'a> + Send + Sync + 'static,
    N: Into<String>,
{
    (
        check_name.into(),
        Box::new(move |ctx| Box::pin(f.call(ctx))),
    )
}

pub async fn check_prompt_is_requested(
    CheckContext {
        prompt, request, ..
    }: CheckContext<'_>,
) -> Result<bool, PromptError> {
    if let Some(requested_prompt) = request.prompt.as_ref() {
        Ok(requested_prompt.contains(&prompt))
    } else {
        Ok(false)
    }
}

pub async fn check_user_is_authenticated(
    CheckContext { user, .. }: CheckContext<'_>,
) -> Result<bool, PromptError> {
    Ok(user.is_none())
}

pub async fn always_run(CheckContext { .. }: CheckContext<'_>) -> Result<bool, PromptError> {
    Ok(true)
}

pub async fn check_user_must_be_authenticated(
    CheckContext { user, request, .. }: CheckContext<'_>,
) -> Result<bool, PromptError> {
    if user.is_none() {
        Err(PromptError::login_required(request))
    } else {
        Ok(false)
    }
}

pub async fn check_user_has_consented(
    CheckContext { user, request, .. }: CheckContext<'_>,
) -> Result<bool, PromptError> {
    let user = user.ok_or(PromptError::login_required(request))?;
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
    CheckContext { user, request, .. }: CheckContext<'_>,
) -> Result<bool, PromptError> {
    let user = user.ok_or(PromptError::login_required(request))?;
    let grant = if let Some(grant_id) = user.grant_id() {
        Grant::find(grant_id).await
    } else {
        None
    };
    if grant.is_none() {
        Err(PromptError::consent_required(request))
    } else {
        Ok(false)
    }
}

pub async fn check_id_token_hint(
    CheckContext {
        user,
        request,
        client,
        config,
        ..
    }: CheckContext<'_>,
) -> Result<bool, PromptError> {
    let Some(user) = user else { return Ok(true) };
    if let Some(hint) = &request.id_token_hint {
        if client.metadata().subject_type == SubjectType::Pairwise {
            let pairwise_resolver = config.pairwise_resolver();
            let pairwise_subject =
                pairwise_resolver.calculate_pairwise_identifier(user.sub(), client)?;
            Ok(!hint
                .payload()
                .subject()
                .is_some_and(|sub| pairwise_subject == *sub))
        } else {
            Ok(!hint
                .payload()
                .subject()
                .is_some_and(|sub| user.sub() == sub))
        }
    } else {
        Ok(false)
    }
}

pub async fn check_sub_id_token_claim(
    CheckContext {
        user,
        request,
        client,
        config,
        ..
    }: CheckContext<'_>,
) -> Result<bool, PromptError> {
    let Some(user) = user else { return Ok(true) };

    let sub_claim = request
        .claims
        .as_ref()
        .and_then(|claims| claims.id_token.get("sub"))
        .and_then(|opts| opts.as_ref())
        .and_then(|opts| opts.value())
        .map(Value::as_str);

    match sub_claim {
        Some(Some(sub)) => {
            let expected_sub = resolve_sub(config, user.sub(), client)?;
            Ok(expected_sub != *sub)
        }
        _ => Ok(false),
    }
}

pub async fn check_max_age(
    CheckContext {
        user,
        request,
        config,
        ..
    }: CheckContext<'_>,
) -> Result<bool, PromptError> {
    let clock = config.clock_provider();
    let user = user.ok_or(PromptError::login_required(request))?;
    let max_age = request.max_age.unwrap_or_else(|| config.auth_max_age());
    let auth_limit = user.auth_time() + Duration::seconds(max_age as i64);
    Ok(clock.now() > auth_limit)
}

pub async fn check_acr_values(
    CheckContext { request, user, .. }: CheckContext<'_>,
) -> Result<bool, PromptError> {
    let user = user.ok_or(PromptError::login_required(request))?;
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
    CheckContext { request, user, .. }: CheckContext<'_>,
) -> Result<bool, PromptError> {
    let user = user.ok_or(PromptError::login_required(request))?;
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
