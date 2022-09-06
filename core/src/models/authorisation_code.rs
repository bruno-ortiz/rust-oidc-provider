use time::OffsetDateTime;
use url::Url;

use oidc_types::client::ClientID;
use oidc_types::code::Code;
use oidc_types::identifiable::Identifiable;
use oidc_types::nonce::Nonce;
use oidc_types::pkce::{CodeChallenge, CodeChallengeMethod};
use oidc_types::scopes::Scopes;
use oidc_types::state::State;
use oidc_types::subject::Subject;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CodeStatus {
    Awaiting,
    Consumed,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthorisationCode {
    pub code: Code,
    pub client_id: ClientID,
    pub subject: Subject,
    pub status: CodeStatus,
    pub code_challenge: Option<CodeChallenge>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub redirect_uri: Url,
    pub scope: Scopes,
    pub expires_in: OffsetDateTime,
    pub nonce: Option<Nonce>,
    pub state: Option<State>,
}

impl AuthorisationCode {
    pub fn is_expired(&self) -> bool {
        let now = OffsetDateTime::now_utc();
        self.expires_in <= now
    }
}

impl Identifiable<Code> for AuthorisationCode {
    fn id(&self) -> Code {
        self.code.clone()
    }
}
