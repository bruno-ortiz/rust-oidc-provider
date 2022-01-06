use oidc_types::authentication_request::AuthenticationRequest;
use oidc_types::client::ClientInformation;
use oidc_types::response_mode::ResponseMode;
use oidc_types::response_type;
use oidc_types::response_type::{ResponseType, ResponseTypeValue};

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

    pub fn response_mode(&self) -> ResponseMode {
        let response_type = &self.request.response_type;
        let response_mode = self
            .request
            .response_mode
            .as_ref()
            .cloned()
            .unwrap_or(response_type.default_response_mode());
        if self.configuration.is_jarm_enabled() {
            response_mode.upgrade(&response_type)
        } else {
            response_mode
        }
    }
}
