use std::sync::Arc;

use axum::extract::{Extension, Query};
use axum::response::Response;

use oidc_core::authorisation_request::AuthorisationRequest;
use oidc_core::configuration::adapter_container::AdapterContainer;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::response_mode::encoder::{DynamicResponseModeEncoder, ResponseModeEncoder};
use oidc_core::response_type::resolver::ResponseTypeResolver;
use oidc_core::services::authorisation::{AuthorisationError, AuthorisationService};
use oidc_types::client::{ClientID, ClientInformation};

use crate::extractors::SessionHolder;
use crate::routes::error::AuthorisationErrorWrapper;

pub async fn authorise<R, E>(
    request: Query<AuthorisationRequest>,
    auth_service: Extension<Arc<AuthorisationService<R, E>>>,
    encoder: Extension<Arc<DynamicResponseModeEncoder>>, //TODO: maybe make auth_service encode the response
    oidc_configuration: Extension<Arc<OpenIDProviderConfiguration>>,
    session: SessionHolder,
) -> Result<Response, AuthorisationErrorWrapper>
where
    R: ResponseTypeResolver,
    E: ResponseModeEncoder,
{
    //     let adapters = oidc_configuration.adapters();
    //     let client_id = request
    //         .client_id
    //         .as_ref()
    //         .ok_or(AuthorisationError::MissingClient)?;
    //     let client = get_client(adapters, client_id).await?;
    //
    //     request
    //         .validate_redirect_uri(&client)
    //         .map_err(|_| AuthorisationError::InvalidRedirectUri)?;
    //
    //     match request.0.validate(&client, &oidc_configuration) {
    //         Ok(req) => {
    //             let user = adapters.user().find(&session.to_string()).await;
    //             match user {
    //                 Some(user) => auth_service.authorise(user, client.clone(), req).await?,
    //                 None => todo!("implement login interaction"),
    //             };
    //             Ok(HttpResponse::Ok().body("Hello"))
    //         }
    //         Err((err, request)) => handle_validation_error(
    //             encoder.into_inner().as_ref(),
    //             &oidc_configuration,
    //             &client,
    //             err,
    //             request,
    //         ),
    //     }
    todo!()
}

// fn handle_validation_error(
//     encoder: &DynamicResponseModeEncoder,
//     oidc_configuration: &OpenIDProviderConfiguration,
//     client: &ClientInformation,
//     err: OpenIdError,
//     request: AuthorisationRequest,
// ) -> Result<HttpResponse, AuthorisationErrorWrapper> {
//     let redirect_uri = request
//         .redirect_uri
//         .as_ref()
//         .ok_or(AuthorisationError::InvalidRedirectUri)?;
//     let response_mode = request
//         .response_type
//         .as_ref()
//         .map_or(ResponseMode::Query, |rt| rt.default_response_mode());
//
//     let encoding_context = EncodingContext {
//         client,
//         configuration: oidc_configuration,
//         redirect_uri,
//         response_mode,
//     };
//     let response = encode_response(encoding_context, encoder, err)?;
//     match response {
//         AuthorisationResponse::Redirect(url) => Ok(HttpResponse::Found()
//             .header(LOCATION, url.as_str())
//             .finish()),
//         AuthorisationResponse::FormPost(_, _) => {
//             todo!()
//         }
//     }
// }

async fn get_client(
    adapters: &AdapterContainer,
    client_id: &ClientID,
) -> Result<Arc<ClientInformation>, AuthorisationError> {
    let client = adapters
        .client()
        .find(client_id)
        .await
        .map(Arc::new)
        .ok_or(AuthorisationError::InvalidClient)?;
    Ok(client)
}
