use std::sync::Arc;

use oidc_types::client::ClientInformation;
use oidc_types::response_type::Flow;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::OpenIDProviderConfiguration;
use crate::session::AuthenticatedUser;

pub struct OpenIDContext {
    pub client: Arc<ClientInformation>,
    pub user: AuthenticatedUser,
    pub request: ValidatedAuthorisationRequest,
    pub configuration: Arc<OpenIDProviderConfiguration>,
}

impl OpenIDContext {
    pub fn new(
        client: Arc<ClientInformation>,
        user: AuthenticatedUser,
        request: ValidatedAuthorisationRequest,
        configuration: Arc<OpenIDProviderConfiguration>,
    ) -> Self {
        OpenIDContext {
            client,
            user,
            request,
            configuration,
        }
    }

    pub fn flow_type(&self) -> Flow {
        self.request.response_type.flow()
    }
}
