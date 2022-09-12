use time::OffsetDateTime;
use url::Url;

use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::client::{AuthenticatedClient, ClientID};
use oidc_types::code::Code;
use oidc_types::identifiable::Identifiable;
use oidc_types::nonce::Nonce;
use oidc_types::pkce::{validate_pkce, CodeChallenge, CodeChallengeMethod};
use oidc_types::scopes::Scopes;
use oidc_types::state::State;
use oidc_types::subject::Subject;
use oidc_types::token_request::AuthorisationCodeGrant;

use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::Status;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthorisationCode {
    pub code: Code,
    pub client_id: ClientID,
    pub subject: Subject,
    pub status: Status,
    pub code_challenge: Option<CodeChallenge>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub redirect_uri: Url,
    pub scopes: Scopes,
    pub expires_in: OffsetDateTime,
    pub nonce: Option<Nonce>,
    pub state: Option<State>,
    pub acr: Acr,
    pub amr: Option<Amr>,
    pub auth_time: OffsetDateTime,
}

impl AuthorisationCode {
    pub fn is_expired(&self) -> bool {
        let now = OffsetDateTime::now_utc();
        self.expires_in <= now
    }

    pub fn validate(
        self,
        client: &AuthenticatedClient,
        grant: &AuthorisationCodeGrant,
    ) -> Result<Self, OpenIdError> {
        if self.status != Status::Awaiting {
            return Err(OpenIdError::invalid_grant(
                "Authorization code already consumed",
            ));
        }
        if self.client_id != client.as_ref().id {
            return Err(OpenIdError::invalid_grant(
                "Client mismatch for authorization code",
            ));
        }
        if self.is_expired() {
            return Err(OpenIdError::invalid_grant("Authorization code is expired"));
        }
        if grant.redirect_uri != self.redirect_uri {
            return Err(OpenIdError::invalid_grant("Redirect uri mismatch"));
        }
        validate_pkce(
            grant,
            self.code_challenge.as_ref(),
            self.code_challenge_method,
        )?;
        Ok(self)
    }

    pub async fn consume(
        mut self,
    ) -> Result<AuthorisationCode, OpenIdError> {
        let configuration = OpenIDProviderConfiguration::instance();
        self.status = Status::Consumed;
        configuration
            .adapters()
            .code()
            .save(self)
            .await
            .map_err(|err| OpenIdError::server_error(err.into()))
    }
}

impl Identifiable<Code> for AuthorisationCode {
    fn id(&self) -> Code {
        self.code.clone()
    }
}
