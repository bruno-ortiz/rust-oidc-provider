use std::borrow::Borrow;
use std::sync::Arc;

use oidc_core::client::ClientService;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::response_mode::encoder::DynamicResponseModeEncoder;
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;
use oidc_core::services::authorisation::AuthorisationService;
use oidc_core::services::interaction::InteractionService;

// use crate::routes::authorisation::authorise;
// use crate::routes::interaction::login_complete;

// pub fn oidc_configuration(
//     oidc_config: OpenIDProviderConfiguration,
// ) -> impl FnOnce(&mut ServiceConfig) {
//     move |cfg: &mut ServiceConfig| {
//         let oidc_config = Arc::new(oidc_config);
//         let routes = oidc_config.routes();
//         let adapter = oidc_config.adapters();
//         let client_service = Arc::new(ClientService::new(adapter.client()));
//         let auth_service = Arc::new(AuthorisationService::new(
//             DynamicResponseTypeResolver::from(oidc_config.borrow()),
//             DynamicResponseModeEncoder::from(oidc_config.borrow()),
//             oidc_config.clone(),
//         ));
//         let interaction_service =
//             InteractionService::new(oidc_config.clone(), auth_service.clone());
//         cfg.app_data(Data::new(client_service));
//         cfg.app_data(Data::new(interaction_service));
//         cfg.app_data(Data::new(DynamicResponseModeEncoder::from(
//             oidc_config.borrow(),
//         )));
//         cfg.app_data(Data::from(auth_service));
//         cfg.app_data(Data::from(oidc_config.clone()));
//         cfg.route(routes.authorisation.as_str(), web::get().to(authorise));
//         cfg.route("interaction/login", web::post().to(login_complete));
//     }
// }
