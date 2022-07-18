use std::sync::Arc;

use axum::extract::{Extension, Query};
use axum::response::{IntoResponse, Redirect, Response, Result};

use oidc_core::authorisation_request::AuthorisationRequest;
use oidc_core::client::retrieve_client_info_by_unparsed;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::response_mode::encoder::{
    encode_response, AuthorisationResponse, DynamicResponseModeEncoder, EncodingContext,
    ResponseModeEncoder,
};
use oidc_core::response_type::errors::OpenIdError;
use oidc_core::response_type::resolver::ResponseTypeResolver;
use oidc_core::services::authorisation::{AuthorisationError, AuthorisationService};
use oidc_types::client::ClientInformation;
use oidc_types::response_mode::ResponseMode;

use crate::extractors::SessionHolder;
use crate::routes::error::AuthorisationErrorWrapper;

// #[axum_macros::debug_handler]
pub async fn authorise<R, E>(
    request: Query<AuthorisationRequest>,
    auth_service: Extension<Arc<AuthorisationService<R, E>>>,
    encoder: Extension<Arc<DynamicResponseModeEncoder>>,
    configuration: Extension<Arc<OpenIDProviderConfiguration>>,
    session: SessionHolder,
) -> Result<Response, AuthorisationErrorWrapper>
where
    R: ResponseTypeResolver,
    E: ResponseModeEncoder,
{
    let client = get_client(&configuration, &request).await?;
    match request.0.validate(&client, &configuration) {
        Ok(req) => {
            let res = auth_service
                .authorise(session.session_id(), client, req)
                .await?;
            Ok(respond(res))
        }
        Err((err, request)) => {
            handle_validation_error(&encoder, &configuration, &client, err, request)
        }
    }
}

fn handle_validation_error(
    encoder: &DynamicResponseModeEncoder,
    oidc_configuration: &OpenIDProviderConfiguration,
    client: &ClientInformation,
    err: OpenIdError,
    request: AuthorisationRequest,
) -> Result<Response, AuthorisationErrorWrapper> {
    let encoding_context = encoding_context(oidc_configuration, client, &request)?;
    let response = encode_response(encoding_context, encoder, err)?;
    Ok(respond(response))
}

fn respond(response: AuthorisationResponse) -> Response {
    match response {
        AuthorisationResponse::Redirect(url) => Redirect::to(url.as_str()).into_response(),
        AuthorisationResponse::FormPost(_, _) => todo!(),
    }
}

fn encoding_context<'a>(
    oidc_configuration: &'a OpenIDProviderConfiguration,
    client: &'a ClientInformation,
    request: &'a AuthorisationRequest,
) -> Result<EncodingContext<'a>, AuthorisationError> {
    let redirect_uri = request
        .redirect_uri
        .as_ref()
        .ok_or(AuthorisationError::InvalidRedirectUri)?;
    let response_mode = request
        .response_type
        .as_ref()
        .map_or(ResponseMode::Query, |rt| rt.default_response_mode());

    Ok(EncodingContext {
        client,
        configuration: oidc_configuration,
        redirect_uri,
        response_mode,
    })
}

async fn get_client(
    configuration: &OpenIDProviderConfiguration,
    request: &AuthorisationRequest,
) -> Result<ClientInformation, AuthorisationError> {
    let client_id = request
        .client_id
        .as_ref()
        .ok_or(AuthorisationError::MissingClient)?;
    retrieve_client_info_by_unparsed(configuration, client_id).await
}
