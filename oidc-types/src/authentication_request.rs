use crate::jose::jws::JWS;
use crate::pkce::CodeChallengeMethod;
use crate::prompt::Prompt;
use crate::response_mode::ResponseMode;
use crate::response_type::ResponseType;
use crate::scopes::Scopes;
use url::Url;

struct AuthenticationRequest {
    response_type: Option<ResponseType>,
    client_id: Option<String>,
    redirect_uri: Option<Url>,
    scope: Option<Scopes>,
    state: Option<String>,
    response_mode: Option<ResponseMode>,
    code_challenge: Option<String>,
    code_challenge_method: Option<CodeChallengeMethod>,
    //rfc8707
    resource: Option<Url>,
    include_granted_scopes: Option<bool>,
    request_uri: Option<Url>,
    request: JWS,
    prompt: Option<Prompt>,
}
