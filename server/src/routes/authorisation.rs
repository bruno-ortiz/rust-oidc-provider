use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response, Result};

use oidc_core::authorisation_request::AuthorisationRequest;
use oidc_core::client::retrieve_client_info_by_unparsed;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::error::OpenIdError;
use oidc_core::models::client::ClientInformation;
use oidc_core::request_object::RequestObjectProcessor;
use oidc_core::response_mode::Authorisation;
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;
use oidc_core::services::authorisation::{AuthorisationError, AuthorisationService};
use oidc_core::services::keystore::KeystoreService;
use oidc_types::response_mode::ResponseMode;
use time::Duration;

use crate::extractors::SessionHolder;
use crate::routes::error::AuthorisationErrorWrapper;

// #[axum_macros::debug_handler]
pub async fn authorise(
    Query(mut request): Query<AuthorisationRequest>,
    State(auth_service): State<Arc<AuthorisationService<DynamicResponseTypeResolver>>>,
    State(provider): State<Arc<OpenIDProviderConfiguration>>,
    State(req_obj_processor): State<Arc<RequestObjectProcessor>>,
    State(keystore_service): State<Arc<KeystoreService>>,
    session: SessionHolder,
) -> Result<AuthorisationResponse, AuthorisationErrorWrapper> {
    let client = Arc::new(get_client(&provider, &request).await?);
    let request_object = req_obj_processor
        .process(&request, &client)
        .await
        .map_err(|err| {
            convert_to_authorisation_error(
                err.into(),
                &mut request,
                provider.clone(),
                keystore_service.clone(),
                client.clone(),
            )
        })?;
    let authorization_request = request_object.unwrap_or(request);
    validate_redirect_uri(&authorization_request, &client)?;

    let validated_request = authorization_request
        .validate(&keystore_service, &client, &provider)
        .await
        .map_err(|(err, mut request)| {
            convert_to_authorisation_error(
                err,
                &mut request,
                provider.clone(),
                keystore_service.clone(),
                client.clone(),
            )
        })?;
    if let Some(max_age) = validated_request.max_age {
        session.set_duration(Duration::seconds(max_age as i64));
    }
    let authorisation = auth_service
        .authorise(session.session_id(), client.clone(), validated_request)
        .await?;
    Ok(AuthorisationResponse(authorisation))
}

fn validate_redirect_uri(
    request: &AuthorisationRequest,
    client: &ClientInformation,
) -> Result<(), AuthorisationError> {
    let redirect_uri = request
        .redirect_uri
        .as_ref()
        .ok_or(AuthorisationError::MissingRedirectUri)?;
    if client.metadata().redirect_uris.contains(redirect_uri) {
        Ok(())
    } else {
        Err(AuthorisationError::InvalidRedirectUri)
    }
}

async fn get_client(
    provider: &OpenIDProviderConfiguration,
    request: &AuthorisationRequest,
) -> Result<ClientInformation, AuthorisationError> {
    let client_id = request
        .client_id
        .as_ref()
        .ok_or(AuthorisationError::MissingClient)?;
    retrieve_client_info_by_unparsed(provider, client_id)
        .await?
        .ok_or_else(|| AuthorisationError::MissingClient)
}

fn convert_to_authorisation_error(
    err: OpenIdError,
    req: &mut AuthorisationRequest,
    provider: Arc<OpenIDProviderConfiguration>,
    keystore_service: Arc<KeystoreService>,
    client: Arc<ClientInformation>,
) -> AuthorisationError {
    let Some(redirect_uri) = req.redirect_uri.take() else {
        return AuthorisationError::MissingRedirectUri;
    };
    let response_mode = req
        .response_type
        .as_ref()
        .map_or(ResponseMode::Query, |rt| rt.default_response_mode());
    AuthorisationError::RedirectableErr {
        err,
        state: req.state.take(),
        provider,
        keystore_service,
        redirect_uri,
        response_mode,
        client,
    }
}

pub(crate) struct AuthorisationResponse(pub(crate) Authorisation);

impl IntoResponse for AuthorisationResponse {
    fn into_response(self) -> Response {
        match self.0 {
            Authorisation::Redirect(url) => Redirect::to(url.as_str()).into_response(),
            Authorisation::FormPost(_, _) => todo!(),
        }
    }
}
