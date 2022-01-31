use std::borrow::Borrow;
use std::sync::Arc;

use actix_web::web;
use actix_web::web::{Data, ServiceConfig};

use oidc_core::authorisation::AuthorisationService;
use oidc_core::client::ClientService;
use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::response_mode::encoder::DynamicResponseModeEncoder;
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;

use crate::routes::authorisation::authorise;

pub fn oidc_configuration(
    oidc_config: OpenIDProviderConfiguration,
) -> impl FnOnce(&mut ServiceConfig) {
    move |cfg: &mut ServiceConfig| {
        let oidc_config = Arc::new(oidc_config);
        let routes = oidc_config.routes();
        let adapter = oidc_config.adapters();
        let client_service = Arc::new(ClientService::new(adapter.client()));
        let auth_service = AuthorisationService::new(
            DynamicResponseTypeResolver::from(oidc_config.borrow()),
            DynamicResponseModeEncoder::from(oidc_config.borrow()),
            client_service.clone(),
            oidc_config.clone(),
        );
        cfg.data(client_service);
        cfg.data(auth_service);
        cfg.app_data(Data::from(oidc_config.clone()));
        cfg.route(routes.authorisation.as_str(), web::get().to(authorise));
    }
}
