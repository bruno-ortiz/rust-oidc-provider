use url::Url;

use oidc_types::jose::jwt::JWT;
use oidc_types::pkce::CodeChallengeMethod;
use oidc_types::prompt::Prompt;
use oidc_types::response_mode::ResponseMode;
use oidc_types::response_type::ResponseType;
use oidc_types::scopes::Scopes;

use crate::state::State;

pub struct AuthenticationRequest {
    pub response_type: Option<ResponseType>,
    pub client_id: Option<String>,
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

impl Default for AuthenticationRequest {
    fn default() -> Self {
        AuthenticationRequest {
            response_type: Option::None,
            client_id: Option::None,
            redirect_uri: Option::None,
            scope: Option::None,
            state: Option::None,
            response_mode: Option::None,
            code_challenge: Option::None,
            code_challenge_method: Option::None,
            resource: Option::None,
            include_granted_scopes: Option::None,
            request_uri: Option::None,
            request: Option::None,
            prompt: Option::None,
        }
    }
}
