use std::fmt::{Display, Formatter};

use derive_builder::Builder;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::claims::Claims;
use oidc_types::client::ClientID;
use oidc_types::identifiable::Identifiable;
use oidc_types::nonce::Nonce;
use oidc_types::scopes::Scopes;
use oidc_types::state::State;
use oidc_types::subject::Subject;

use crate::adapter::PersistenceError;
use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::client::AuthenticatedClient;
use crate::models::{Status, Token};

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
#[builder(setter(into))]
pub struct RefreshToken {
    pub token: String,
    pub client_id: ClientID,
    #[builder(default)]
    pub status: Status,
    pub subject: Subject,
    pub redirect_uri: Url,
    pub scopes: Scopes,
    pub expires_in: OffsetDateTime,
    pub created: OffsetDateTime,
    pub acr: Acr,
    pub nonce: Option<Nonce>,
    pub state: Option<State>,
    pub amr: Option<Amr>,
    pub auth_time: OffsetDateTime,
    pub claims: Option<Claims>,
    pub max_age: Option<u64>,
}

impl RefreshToken {
    pub fn new_from(old_rt: RefreshToken) -> Result<Self, OpenIdError> {
        RefreshTokenBuilder::default()
            .token(Uuid::new_v4().to_string())
            .status(Status::Awaiting)
            .redirect_uri(old_rt.redirect_uri)
            .client_id(old_rt.client_id)
            .subject(old_rt.subject)
            .scopes(old_rt.scopes)
            .state(old_rt.state)
            .amr(old_rt.amr)
            .acr(old_rt.acr)
            .nonce(old_rt.nonce)
            .expires_in(old_rt.expires_in)
            .created(old_rt.created)
            .auth_time(old_rt.auth_time)
            .claims(old_rt.claims)
            .max_age(old_rt.max_age)
            .build()
            .map_err(OpenIdError::server_error)
    }

    pub async fn save(self) -> Result<RefreshToken, PersistenceError> {
        let configuration = OpenIDProviderConfiguration::instance();
        configuration.adapters().refresh().save(self).await
    }

    pub fn is_expired(&self) -> bool {
        let clock = OpenIDProviderConfiguration::clock();
        let now = clock.now();
        self.expires_in <= now
    }

    pub async fn consume(mut self) -> Result<RefreshToken, OpenIdError> {
        let configuration = OpenIDProviderConfiguration::instance();
        self.status = Status::Consumed;
        configuration
            .adapters()
            .refresh()
            .save(self)
            .await
            .map_err(OpenIdError::server_error)
    }

    pub async fn validate(self, client: &AuthenticatedClient) -> Result<Self, OpenIdError> {
        if self.status == Status::Consumed {
            //TODO: invalidate entire token chain
            return Err(OpenIdError::invalid_grant("Refresh token already used"));
        }
        if self.client_id != client.id() {
            return Err(OpenIdError::invalid_grant(
                "Client mismatch for refresh token",
            ));
        }
        if self.is_expired() {
            return Err(OpenIdError::invalid_grant("Refresh token is expired"));
        }
        Ok(self)
    }

    pub fn total_lifetime(&self) -> Duration {
        let clock = OpenIDProviderConfiguration::clock();
        let now = clock.now();
        now - self.created
    }

    pub fn ttl_elapsed(&self) -> f64 {
        let clock = OpenIDProviderConfiguration::clock();
        let created = self.created;
        let due_date = self.expires_in;
        let partial = (clock.now() - created).as_seconds_f64();
        let total_duration = (due_date - created).as_seconds_f64();
        total_duration * 100.0 / partial
    }
}

impl Identifiable<String> for RefreshToken {
    fn id(&self) -> String {
        self.token.clone()
    }
}

impl Display for RefreshToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.token)
    }
}

impl Token for RefreshToken {
    fn subject(&self) -> &Subject {
        &self.subject
    }

    fn auth_time(&self) -> u64 {
        self.auth_time.unix_timestamp() as u64
    }

    fn acr(&self) -> &Acr {
        &self.acr
    }

    fn amr(&self) -> Option<&Amr> {
        self.amr.as_ref()
    }

    fn scopes(&self) -> &Scopes {
        &self.scopes
    }

    fn claims(&self) -> Option<&Claims> {
        self.claims.as_ref()
    }

    fn nonce(&self) -> Option<&Nonce> {
        self.nonce.as_ref()
    }
}
