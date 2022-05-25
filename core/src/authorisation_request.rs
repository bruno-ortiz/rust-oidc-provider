use anyhow::anyhow;
use serde::Deserialize;
use url::Url;

use oidc_types::client::{ClientID, ClientInformation};
use oidc_types::jose::jwt::JWT;
use oidc_types::pkce::{CodeChallenge, CodeChallengeMethod};
use oidc_types::prompt::Prompt;
use oidc_types::response_mode::ResponseMode;
use oidc_types::response_type::ResponseType;
use oidc_types::scopes::Scopes;
use oidc_types::state::State;

use crate::configuration::OpenIDProviderConfiguration;
use crate::response_type::errors::OpenIdError;

#[derive(Debug, Clone)]
pub struct ValidatedAuthorisationRequest {
    pub response_type: ResponseType,
    pub client_id: ClientID,
    pub redirect_uri: Url,
    pub scope: Scopes,
    pub state: Option<State>,
    pub response_mode: Option<ResponseMode>,
    pub code_challenge: Option<CodeChallenge>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub resource: Option<Url>,
    //rfc8707
    pub include_granted_scopes: Option<bool>,
    pub request_uri: Option<Url>,
    pub request: Option<JWT>,
    pub prompt: Option<Prompt>,
}

impl ValidatedAuthorisationRequest {
    pub fn response_mode(&self, is_jarm_enabled: bool) -> ResponseMode {
        let response_type = &self.response_type;
        let response_mode = self
            .response_mode
            .as_ref()
            .cloned()
            .unwrap_or_else(|| response_type.default_response_mode());
        if is_jarm_enabled {
            //todo:server or client should enable jarm??
            response_mode.upgrade(response_type)
        } else {
            response_mode
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthorisationRequest {
    pub response_type: Option<ResponseType>,
    pub client_id: Option<ClientID>,
    pub redirect_uri: Option<Url>,
    pub scope: Option<Scopes>,
    pub state: Option<State>,
    pub response_mode: Option<ResponseMode>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub resource: Option<Url>,
    //rfc8707
    pub include_granted_scopes: Option<bool>,
    pub request_uri: Option<Url>,
    pub request: Option<JWT>,
    pub prompt: Option<Prompt>,
}

impl AuthorisationRequest {
    pub fn validate(
        self,
        client: &ClientInformation,
        configuration: &OpenIDProviderConfiguration,
    ) -> Result<ValidatedAuthorisationRequest, (OpenIdError, Self)> {
        if let Err(err) = self.validate_response_type(client, configuration) {
            return Err((err, self));
        }
        if let Err(err) = self.validate_scopes(client) {
            return Err((err, self));
        }
        if self.client_id.is_none() {
            return Err((
                OpenIdError::InvalidRequest {
                    description: "Missing client_id",
                },
                self,
            ));
        }
        if let Err(err) = self.validate_redirect_uri(client) {
            return Err((err, self));
        }

        Ok(ValidatedAuthorisationRequest {
            response_type: self.response_type.expect("Response type not found"),
            client_id: self.client_id.expect("ClientId not found"),
            redirect_uri: self.redirect_uri.expect("Redirect URI not found"),
            scope: self.scope.expect("Scope not found"),
            state: self.state,
            response_mode: self.response_mode,
            code_challenge: self.code_challenge.map(CodeChallenge::new),
            code_challenge_method: self.code_challenge_method,
            resource: self.resource,
            include_granted_scopes: self.include_granted_scopes,
            request_uri: self.request_uri,
            request: self.request,
            prompt: self.prompt,
        })
    }

    fn validate_redirect_uri(&self, client: &ClientInformation) -> Result<(), OpenIdError> {
        let redirect_uri = self
            .redirect_uri
            .as_ref()
            .ok_or(OpenIdError::InvalidRequest {
                description: "Missing redirect_uri",
            })?;
        if client.metadata.redirect_uris.contains(redirect_uri) {
            Ok(())
        } else {
            Err(OpenIdError::InvalidRequest {
                description: "Redirect uri not registered for client",
            })
        }
    }

    fn validate_response_type(
        &self,
        client: &ClientInformation,
        configuration: &OpenIDProviderConfiguration,
    ) -> Result<(), OpenIdError> {
        match self.response_type {
            None => Err(OpenIdError::InvalidRequest {
                description: "Missing response type",
            }),
            Some(ref rt) => {
                if !AuthorisationRequest::server_allows_response_type(configuration, rt) {
                    return Err(OpenIdError::UnsupportedResponseType(rt.clone()));
                }
                let response_type_allowed = rt
                    .iter()
                    .all(|item| client.metadata.response_types.contains(item));
                if response_type_allowed {
                    Ok(())
                } else {
                    Err(OpenIdError::UnauthorizedClient {
                        source: anyhow!("Response type not allowed for client {}", rt),
                    })
                }
            }
        }
    }

    fn validate_scopes(&self, client: &ClientInformation) -> Result<(), OpenIdError> {
        match self.scope {
            None => Err(OpenIdError::InvalidRequest {
                description: "Missing scope",
            }),
            Some(ref scopes) => {
                let invalid_scope = scopes
                    .iter()
                    .find(|&item| !client.metadata.scope.contains(item));
                match invalid_scope {
                    None => Ok(()),
                    Some(scope) => Err(OpenIdError::InvalidScope(scope.clone())),
                }
            }
        }
    }

    fn server_allows_response_type(
        configuration: &OpenIDProviderConfiguration,
        response_type: &ResponseType,
    ) -> bool {
        configuration.response_types().contains(response_type)
    }
}
