use std::fmt::{Display, Formatter};

use derive_builder::Builder;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use oidc_types::identifiable::Identifiable;
use oidc_types::nonce::Nonce;
use oidc_types::scopes::Scopes;
use oidc_types::state::State;

use crate::configuration::clock::{Clock, ClockProvider};
use crate::error::OpenIdError;
use crate::models::grant::GrantID;
use crate::models::Status;

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
#[builder(setter(into))]
pub struct RefreshToken {
    pub token: Uuid,
    pub grant_id: GrantID,
    #[builder(default)]
    pub status: Status,
    pub expires_in: OffsetDateTime,
    pub created: OffsetDateTime,
    pub state: Option<State>,
    pub nonce: Option<Nonce>,
    pub scopes: Scopes,
}

impl RefreshToken {
    pub fn new_from(old_rt: RefreshToken) -> Result<Self, OpenIdError> {
        RefreshTokenBuilder::default()
            .token(Uuid::new_v4())
            .grant_id(old_rt.grant_id)
            .status(Status::Awaiting)
            .state(old_rt.state)
            .nonce(old_rt.nonce)
            .scopes(old_rt.scopes)
            .expires_in(old_rt.expires_in)
            .created(old_rt.created)
            .build()
            .map_err(OpenIdError::server_error)
    }

    pub fn is_expired(&self, clock: &ClockProvider) -> bool {
        let now = clock.now();
        self.expires_in <= now
    }

    pub fn total_lifetime(&self, clock: &ClockProvider) -> Duration {
        let now = clock.now();
        now - self.created
    }

    pub fn ttl_elapsed(&self, clock: &ClockProvider) -> f64 {
        let created = self.created;
        let due_date = self.expires_in;
        let partial = (clock.now() - created).as_seconds_f64();
        let total_duration = (due_date - created).as_seconds_f64();
        total_duration * 100.0 / partial
    }
}

impl Identifiable<Uuid> for RefreshToken {
    fn id(&self) -> &Uuid {
        &self.token
    }
}

impl Display for RefreshToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.token)
    }
}
