use std::str::FromStr;

use indexmap::IndexSet;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tracing::error;
use url::Url;

use oidc_types::acr::Acr;
use oidc_types::claims::Claims;
use oidc_types::client::ClientID;
use oidc_types::grant_type::GrantType;
use oidc_types::jose::jws::SigningAlgorithm;
use oidc_types::nonce::Nonce;
use oidc_types::pkce::{CodeChallenge, CodeChallengeMethod};
use oidc_types::prompt::Prompt;
use oidc_types::response_mode::ResponseMode;
use oidc_types::response_type::{Flow, ResponseType};
use oidc_types::scopes::Scopes;
use oidc_types::simple_id_token::SimpleIdToken;
use oidc_types::state::State;

use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::jwt::{GenericJWT, ValidJWT};
use crate::models::client::ClientInformation;
use crate::services::keystore::KeystoreService;
use crate::utils::get_jose_algorithm;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValidatedAuthorisationRequest {
    pub response_type: ResponseType,
    pub client_id: ClientID,
    pub redirect_uri: Url,
    pub scope: Scopes,
    pub state: Option<State>,
    pub nonce: Option<Nonce>,
    pub response_mode: Option<ResponseMode>,
    pub code_challenge: Option<CodeChallenge>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub max_age: Option<u64>,
    pub resource: Option<Url>,
    pub id_token_hint: Option<SimpleIdToken>,
    pub login_hint: Option<String>,
    //rfc8707
    pub include_granted_scopes: Option<bool>,
    pub prompt: Option<IndexSet<Prompt>>,
    pub acr_values: Option<Acr>,
    pub claims: Option<Claims>,
}

impl ValidatedAuthorisationRequest {
    pub fn response_mode(&self, is_jarm_enabled: bool) -> Result<ResponseMode, OpenIdError> {
        let response_type = &self.response_type;
        let response_mode = self
            .response_mode
            .as_ref()
            .cloned()
            .unwrap_or_else(|| response_type.default_response_mode());
        if is_jarm_enabled {
            Ok(response_mode.upgrade(response_type))
        } else {
            if response_mode.is_jwt() {
                return Err(OpenIdError::invalid_request(
                    "JWT response mode is not supported",
                ));
            }
            Ok(response_mode)
        }
    }

    pub fn id_token_hint(
        &self,
        keystore_service: &KeystoreService,
        client: &ClientInformation,
    ) -> Result<Option<ValidJWT<GenericJWT>>, OpenIdError> {
        validate_id_token_hint(
            keystore_service,
            self.id_token_hint.as_ref().map(|it| it.as_ref()),
            client,
        )
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthorisationRequest {
    pub response_type: Option<ResponseType>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<Url>,
    pub scope: Option<Scopes>,
    pub state: Option<State>,
    pub nonce: Option<Nonce>,
    pub response_mode: Option<ResponseMode>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub max_age: Option<u64>,
    pub resource: Option<Url>,
    //rfc8707
    pub include_granted_scopes: Option<bool>,
    pub request_uri: Option<Url>,
    pub request: Option<String>,
    pub prompt: Option<String>,
    pub acr_values: Option<Acr>,
    pub claims: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
}

impl AuthorisationRequest {
    pub async fn validate(
        self,
        keystore_service: &KeystoreService,
        client: &ClientInformation,
        provider: &OpenIDProviderConfiguration,
    ) -> Result<ValidatedAuthorisationRequest, (OpenIdError, Self)> {
        let this = self;
        if let Err(err) = this.validate_response_type(provider, client) {
            return Err((err, this));
        }
        if let Err(err) = this.validate_scopes(client) {
            return Err((err, this));
        }
        if this.client_id.is_none() {
            return Err((OpenIdError::invalid_request("Missing client_id"), this));
        }

        const MIN_ENTROPY: usize = 43;
        if let Some(ref challenge) = this.code_challenge {
            if challenge.len() < MIN_ENTROPY {
                return Err((
                    OpenIdError::invalid_request("Code challenge must have a minimum length of 43"),
                    this,
                ));
            }
        }

        let prompt = this
            .prompt
            .as_ref()
            .map(|p| p.split(' ').map(Prompt::try_from).collect::<Vec<_>>());

        if let Some(ref prompt) = prompt {
            if let Some(Err(err)) = prompt.iter().find(|&it| it.is_err()) {
                error!("Err parsing prompt {}", err);
                return Err((OpenIdError::invalid_request("Invalid prompt"), this));
            }
        }
        let prompt: Option<IndexSet<Prompt>> =
            prompt.map(|it| it.into_iter().flatten().sorted().collect());
        if let Some(prompt) = prompt.as_ref() {
            if prompt.contains(&Prompt::None) && prompt.len() > 1 {
                return Err((
                    OpenIdError::invalid_request(
                        "Prompt 'none' cannot be combined with other prompt values",
                    ),
                    this,
                ));
            }
        }
        let claims = match parse_claims(provider, &this) {
            Ok(c) => c,
            Err(err) => return Err((err, this)),
        };

        let id_token_hint =
            match validate_id_token_hint(keystore_service, this.id_token_hint.as_deref(), client) {
                Ok(validated_jwt) => validated_jwt,
                Err(err) => return Err((err, this)),
            };
        let id_token_hint = id_token_hint.map(|it| SimpleIdToken::new(it.serialized()));
        Ok(ValidatedAuthorisationRequest {
            response_type: this.response_type.expect("Response type not found"),
            client_id: this
                .client_id
                .map(|cid| ClientID::from_str(&cid).expect("Invalid ClientID"))
                .expect("ClientId not found"),
            redirect_uri: this.redirect_uri.expect("Redirect URI not found"),
            scope: this.scope.expect("Scope not found"),
            state: this.state,
            nonce: this.nonce,
            id_token_hint,
            response_mode: this.response_mode,
            code_challenge: this.code_challenge.map(CodeChallenge::new),
            code_challenge_method: this.code_challenge_method,
            resource: this.resource,
            include_granted_scopes: this.include_granted_scopes,
            acr_values: this.acr_values,
            max_age: this.max_age,
            login_hint: this.login_hint,
            prompt,
            claims,
        })
    }

    fn validate_response_type(
        &self,
        configuration: &OpenIDProviderConfiguration,
        client: &ClientInformation,
    ) -> Result<(), OpenIdError> {
        match self.response_type {
            None => Err(OpenIdError::invalid_request("Missing response type")),
            Some(ref rt) => {
                if !AuthorisationRequest::server_allows_response_type(configuration, rt) {
                    return Err(OpenIdError::unsupported_response_type(
                        "Unsupported response type",
                    ));
                }
                let flow_type = rt.flow();
                if flow_type == Flow::Implicit
                    && client.metadata().grant_types.contains(&GrantType::Implicit)
                {
                    return Err(OpenIdError::invalid_request(
                        "Client not allowed to execute a implicit flow",
                    ));
                }
                let response_type_allowed = rt
                    .iter()
                    .all(|item| client.metadata().response_types.contains(item));
                if response_type_allowed {
                    Ok(())
                } else {
                    Err(OpenIdError::unauthorized_client(
                        "Response type not allowed for client",
                    ))
                }
            }
        }
    }

    fn validate_scopes(&self, client: &ClientInformation) -> Result<(), OpenIdError> {
        match self.scope {
            None => Err(OpenIdError::invalid_request("Missing scope")),
            Some(ref scopes) => {
                let invalid_scope = scopes
                    .iter()
                    .find(|&item| !client.metadata().scope.contains(item));
                match invalid_scope {
                    None => Ok(()),
                    Some(scope) => Err(OpenIdError::invalid_scope(format!(
                        "Unsupported scope {} for client {}",
                        scope,
                        client.id()
                    ))),
                }
            }
        }
    }

    fn server_allows_response_type(
        configuration: &OpenIDProviderConfiguration,
        response_type: &ResponseType,
    ) -> bool {
        configuration
            .response_types_supported()
            .contains(response_type)
    }
}

fn parse_claims(
    config: &OpenIDProviderConfiguration,
    this: &AuthorisationRequest,
) -> Result<Option<Claims>, OpenIdError> {
    let claims = if let Some(ref c) = this.claims {
        if !config.claims_parameter_supported() {
            return Err(OpenIdError::invalid_request(
                "Claims parameter not supported in authorization request",
            ));
        }
        match serde_json::from_str::<Claims>(c) {
            Ok(claims) => Some(claims),
            Err(err) => {
                error!("Error parsing claims request {:?}", err);
                return Err(OpenIdError::invalid_request("Invalid claims parameter"));
            }
        }
    } else {
        None
    };
    Ok(claims)
}

fn validate_id_token_hint(
    keystore_service: &KeystoreService,
    id_token: Option<&str>,
    client: &ClientInformation,
) -> Result<Option<ValidJWT<GenericJWT>>, OpenIdError> {
    if let Some(hint) = id_token {
        let alg = get_alg(hint)?;
        let keystore = keystore_service.server_keystore(client, &alg);
        let jwt = GenericJWT::parse(hint, &keystore).map_err(OpenIdError::server_error)?;
        let valid_jwt = ValidJWT::validate(jwt, &keystore).map_err(OpenIdError::server_error)?;
        Ok(Some(valid_jwt))
    } else {
        Ok(None)
    }
}

fn get_alg(id_token: &str) -> Result<SigningAlgorithm, OpenIdError> {
    let alg = get_jose_algorithm(id_token)
        .map_err(|err| OpenIdError::invalid_request(err.to_string()))?
        .ok_or_else(|| OpenIdError::invalid_request("Missing alg in IdToken header."))?;
    Ok(alg)
}
