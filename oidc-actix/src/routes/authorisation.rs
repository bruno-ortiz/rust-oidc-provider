
use std::sync::Arc;

use actix_web::web::Query;
use actix_web::{web, HttpResponse, ResponseError};
use thiserror::Error;

use oidc_core::authorisation::{AuthorisationError, AuthorisationService};
use oidc_core::authorisation_request::AuthorisationRequest;
use oidc_core::client::ClientService;
use oidc_core::response_mode::encoder::DynamicResponseModeEncoder;
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;
use oidc_core::user::find_user_by_session;

use crate::extractors::SessionHolder;

#[derive(Error, Debug)]
#[error(transparent)]
pub struct AuthorisationErrorWrapper(#[from] AuthorisationError);

impl ResponseError for AuthorisationErrorWrapper {}

pub async fn authorise(
    request: Query<AuthorisationRequest>,
    auth_service: web::Data<
        AuthorisationService<DynamicResponseTypeResolver, DynamicResponseModeEncoder>,
    >,
    client_service: web::Data<ClientService>,
    SessionHolder(session): SessionHolder,
) -> Result<HttpResponse, AuthorisationErrorWrapper> {
    let client_id = request
        .client_id
        .as_ref()
        .ok_or(AuthorisationError::MissingClient)?;
    let client = client_service
        .retrieve_client_info(client_id)
        .await
        .ok_or(AuthorisationError::InvalidClient)
        .map(Arc::new)?;

    let user = find_user_by_session(&session);
    match user {
        Some(user) => {
            auth_service
                .authorise(user, client.clone(), request.into_inner())
                .await?
        }
        None => todo!("implement login interaction"),
    };
    Ok(HttpResponse::Ok().body("Hello"))
}
