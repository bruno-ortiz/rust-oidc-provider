use std::sync::Arc;

use axum_macros::FromRef;

use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_core::manager::access_token_manager::AccessTokenManager;
use oidc_core::manager::auth_code_manager::AuthorisationCodeManager;
use oidc_core::manager::grant_manager::GrantManager;
use oidc_core::manager::refresh_token_manager::RefreshTokenManager;
use oidc_core::request_object::RequestObjectProcessor;
use oidc_core::response_mode::encoder::DynamicResponseModeEncoder;
use oidc_core::response_type::resolver::DynamicResponseTypeResolver;
use oidc_core::services::authorisation::AuthorisationService;
use oidc_core::services::interaction::InteractionService;
use oidc_core::services::keystore::KeystoreService;
use oidc_core::services::prompt::PromptService;
use oidc_core::services::token::TokenService;
use oidc_core::services::userinfo::UserInfoService;

#[derive(Clone, FromRef)]
pub(crate) struct AppState {
    provider: Arc<OpenIDProviderConfiguration>,
    authorisation_service:
        Arc<AuthorisationService<DynamicResponseTypeResolver, DynamicResponseModeEncoder>>,
    interaction_service: Arc<InteractionService>,
    token_service: Arc<TokenService>,
    userinfo_service: Arc<UserInfoService>,
    request_object_processor: Arc<RequestObjectProcessor>,
    keystore_service: Arc<KeystoreService>,
}

impl AppState {
    pub fn new(provider: Arc<OpenIDProviderConfiguration>) -> Self {
        let keystore_service = Arc::new(KeystoreService::new(provider.clone()));
        let grant_manager = Arc::new(GrantManager::new(provider.clone()));
        let at_manager = Arc::new(AccessTokenManager::new(provider.clone()));
        let rt_manager = Arc::new(RefreshTokenManager::new(provider.clone()));
        let ac_manager = Arc::new(AuthorisationCodeManager::new(provider.clone()));
        let prompt_service = Arc::new(PromptService::new(
            provider.clone(),
            keystore_service.clone(),
        ));
        let interaction_service = Arc::new(InteractionService::new(
            provider.clone(),
            prompt_service.clone(),
        ));
        let authorisation_service = Arc::new(AuthorisationService::new(
            DynamicResponseTypeResolver::from(provider.as_ref()),
            DynamicResponseModeEncoder,
            provider.clone(),
            interaction_service.clone(),
            grant_manager.clone(),
            keystore_service.clone(),
        ));
        let token_service = Arc::new(TokenService::new(
            provider.clone(),
            grant_manager.clone(),
            at_manager.clone(),
            rt_manager.clone(),
            ac_manager.clone(),
            keystore_service.clone(),
        ));
        let userinfo_service = Arc::new(UserInfoService::new(
            provider.clone(),
            keystore_service.clone(),
        ));
        let request_object_processor = Arc::new(RequestObjectProcessor::new(
            provider.clone(),
            keystore_service.clone(),
        ));
        Self {
            provider,
            authorisation_service,
            interaction_service,
            token_service,
            userinfo_service,
            request_object_processor,
            keystore_service,
        }
    }
}
