use actix_web::{web, HttpRequest, HttpResponse};

use oidc_core::authorisation::AuthorisationService;
use oidc_core::response_mode::encoder::DynamicResponseModeEncoder;
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;

use crate::session::UserSession;

pub(crate) async fn authorise(
    req: HttpRequest,
    auth_service: web::Data<
        AuthorisationService<DynamicResponseTypeResolver, DynamicResponseModeEncoder>,
    >,
    session: UserSession,
) -> HttpResponse {
    match session {
        UserSession::Authenticated(id, sub) => {
            // prompt=login,consent,none
            // verifica prompt, e começa interação
            // executa auth service e pega os códigos/tokens
            // executa encoder e pega url
        }
        UserSession::NotAuthenticated(id) => {
            //begin interaction login flow
        }
    }
    HttpResponse::Ok().body("Hello")
}
