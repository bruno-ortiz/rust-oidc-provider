use crate::response_type::ResponseType;
use url::Url;
use crate::scopes::types::{Scope, Scopes};
use crate::response_mode::ResponseMode;
use crate::pkce::CodeChallengeMethod;
use josekit::jws::{JwsSigner, JwsHeader};
use josekit::jwt::JwtPayload;
use crate::jws::JWS;
use crate::prompt::Prompt;

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