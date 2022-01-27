use std::collections::HashMap;

use url::Url;

use oidc_types::client::ClientID;
use oidc_types::hash::Hashable;
use oidc_types::pkce::{CodeChallenge, CodeChallengeMethod};
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;

use crate::response_type::UrlEncodable;

#[derive(Debug, Clone)]
pub enum CodeStatus {
    Awaiting,
    Consumed,
}

#[derive(Debug, Clone)]
pub struct AuthorisationCode {
    pub code: String,
    pub client_id: ClientID,
    pub subject: Subject,
    pub status: CodeStatus,
    pub code_challenge: CodeChallenge,
    pub code_challenge_method: CodeChallengeMethod,
    pub redirect_uri: Url,
    pub scope: Scopes,
}

impl Hashable for AuthorisationCode {
    fn identifier(&self) -> &str {
        &self.code
    }
}

impl UrlEncodable for AuthorisationCode {
    fn params(self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("code".to_owned(), self.code);
        map
    }
}
