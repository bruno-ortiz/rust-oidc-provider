use url::Url;

use crate::jose::jwt::JWT;
use crate::pkce::CodeChallengeMethod;
use crate::prompt::Prompt;
use crate::response_mode::ResponseMode;
use crate::response_type::{ResponseType, ResponseTypeValue};
use crate::scopes::Scopes;
use crate::state::State;

pub struct AuthenticationRequest {
    pub response_type: ResponseType,
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
