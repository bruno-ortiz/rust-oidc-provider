use std::sync::Arc;

use oidc_types::client::ClientInformation;
use oidc_types::response_type::ResponseType;
use oidc_types::subject::Subject;

use crate::authorisation_request::ValidatedAuthorisationRequest;
use crate::configuration::OpenIDProviderConfiguration;

#[derive(Debug)]
pub struct OpenIDContext {
    pub client: Arc<ClientInformation>,
    pub subject: Subject,
    pub request: ValidatedAuthorisationRequest,
    pub configuration: Arc<OpenIDProviderConfiguration>,
}

impl OpenIDContext {
    pub fn new(
        client: Arc<ClientInformation>,
        subject: Subject,
        request: ValidatedAuthorisationRequest,
        configuration: Arc<OpenIDProviderConfiguration>,
    ) -> Self {
        OpenIDContext {
            client,
            subject,
            request,
            configuration,
        }
    }

    pub fn server_allows_response_type(&self, response_type: &ResponseType) -> bool {
        self.configuration.response_types().contains(response_type)
    }
    pub fn client_allows_response_type(&self, response_type: &ResponseType) -> bool {
        response_type
            .iter()
            .all(|value| self.client.metadata.response_types.contains(value))
    }
}
