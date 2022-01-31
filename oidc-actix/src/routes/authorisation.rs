use actix_web::{web, HttpRequest, HttpResponse};

use oidc_core::authorisation::AuthorisationService;
use oidc_core::response_mode::encoder::DynamicResponseModeEncoder;
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;

pub(crate) async fn authorise(
    req: HttpRequest,
    auth_service: web::Data<
        AuthorisationService<DynamicResponseTypeResolver, DynamicResponseModeEncoder>,
    >,
) -> HttpResponse {
    HttpResponse::Ok().body("Hello")
}
