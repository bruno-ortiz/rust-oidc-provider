use time::OffsetDateTime;

use oidc_types::code::Code;
use oidc_types::identifiable::Identifiable;
use oidc_types::nonce::Nonce;
use oidc_types::pkce::{validate_pkce, CodeChallenge, CodeChallengeMethod};
use oidc_types::scopes::Scopes;
use oidc_types::state::State;
use oidc_types::token_request::AuthorisationCodeGrant;

use crate::configuration::clock::{Clock, ClockProvider};
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::grant::GrantID;
use crate::models::Status;

#[derive(Debug, Clone)]
pub struct AuthorisationCode {
    pub id: Option<u64>,
    pub code: Code,
    pub grant_id: GrantID,
    pub status: Status,
    pub code_challenge: Option<CodeChallenge>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub expires_in: OffsetDateTime,
    pub scopes: Scopes,
    pub state: Option<State>,
    pub nonce: Option<Nonce>,
}

impl Identifiable<Code> for AuthorisationCode {
    fn id(&self) -> &Code {
        &self.code
    }
}
