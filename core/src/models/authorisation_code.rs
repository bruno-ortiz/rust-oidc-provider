use time::OffsetDateTime;

use oidc_types::code::Code;
use oidc_types::identifiable::Identifiable;
use oidc_types::nonce::Nonce;
use oidc_types::pkce::{validate_pkce, CodeChallenge, CodeChallengeMethod};
use oidc_types::scopes::Scopes;
use oidc_types::state::State;
use oidc_types::token_request::AuthorisationCodeGrant;

use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::grant::GrantID;
use crate::models::Status;

#[derive(Debug, Clone)]
pub struct AuthorisationCode {
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

impl AuthorisationCode {
    pub fn is_expired(&self) -> bool {
        let clock = OpenIDProviderConfiguration::clock();
        let now = clock.now();
        self.expires_in <= now
    }

    pub fn validate(self, grant: &AuthorisationCodeGrant) -> Result<Self, OpenIdError> {
        if self.is_expired() {
            return Err(OpenIdError::invalid_grant("Authorization code is expired"));
        }
        validate_pkce(
            grant,
            self.code_challenge.as_ref(),
            self.code_challenge_method,
        )?;
        Ok(self)
    }

    pub async fn consume(mut self) -> Result<AuthorisationCode, OpenIdError> {
        let configuration = OpenIDProviderConfiguration::instance();
        self.status = Status::Consumed;
        configuration
            .adapters()
            .code()
            .save(self)
            .await
            .map_err(OpenIdError::server_error)
    }
}

impl Identifiable<Code> for AuthorisationCode {
    fn id(&self) -> Code {
        self.code.clone()
    }
}
