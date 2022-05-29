

use serde::Deserialize;
use uuid::Uuid;



use oidc_types::subject::Subject;



#[derive(Deserialize)]
pub struct LoginComplete {
    interaction_id: Uuid,
    subject: Subject,
}

// pub async fn login_complete(
//     interaction_service: web::Data<InteractionService>,
//     login_complete: Json<LoginComplete>,
//     oidc_configuration: web::Data<OpenIDProviderConfiguration>,
// ) -> Result<HttpResponse, AuthorisationErrorWrapper> {
//     let LoginComplete {
//         interaction_id,
//         subject,
//     } = login_complete.0;
//
//     let url = interaction_service.complete_login(interaction_id, subject)?;
//     Ok(HttpResponse::Found()
//         .header(LOCATION, url.as_str())
//         .finish())
// }
