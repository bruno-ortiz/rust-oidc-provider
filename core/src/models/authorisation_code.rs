use indexmap::IndexMap;
use time::OffsetDateTime;

use oidc_types::client::ClientID;
use oidc_types::hash::Hashable;
use url::Url;

use oidc_types::identifiable::Identifiable;
use oidc_types::nonce::Nonce;
use oidc_types::pkce::{CodeChallenge, CodeChallengeMethod};
use oidc_types::scopes::Scopes;
use oidc_types::state::State;
use oidc_types::subject::Subject;

use oidc_types::url_encodable::UrlEncodable;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CodeStatus {
    Awaiting,
    Consumed,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthorisationCode {
    pub code: String,
    pub client_id: ClientID,
    pub subject: Subject,
    pub status: CodeStatus,
    pub code_challenge: Option<CodeChallenge>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub redirect_uri: Url,
    pub scope: Scopes,
    pub expires_in: OffsetDateTime,
    pub nonce: Option<Nonce>,
    pub state: Option<State>
}

impl AuthorisationCode {
    pub fn is_expired(&self) -> bool {
        let now = OffsetDateTime::now_utc();
        self.expires_in <= now
    }
}

impl Hashable for AuthorisationCode {
    fn identifier(&self) -> &str {
        &self.code
    }
}

impl UrlEncodable for AuthorisationCode {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("code".to_owned(), self.code);
        map
    }
}

impl Identifiable<String> for AuthorisationCode {
    fn id(&self) -> String {
        self.code.clone()
    }
}
