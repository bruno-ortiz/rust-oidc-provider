use crate::authentication_request::AuthenticationRequest;
use oidc_types::client::ClientInformation;
use oidc_types::response_type::ResponseType;

use crate::configuration::OpenIDProviderConfiguration;

pub struct OpenIDContext {
    pub client: ClientInformation,
    pub request: AuthenticationRequest,
    pub configuration: OpenIDProviderConfiguration,
}

impl OpenIDContext {
    pub fn allows_response_type(&self, response_type: &ResponseType) -> bool {
        self.configuration.response_types().contains(response_type)
            && response_type
                .iter()
                .all(|value| self.client.metadata.response_types.contains(value))
    }
}
