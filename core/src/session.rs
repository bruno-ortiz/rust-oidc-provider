use std::fmt::{Display, Formatter};
use std::str::FromStr;

use oidc_types::identifiable::Identifiable;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::{Error as UuidError, Uuid};

use oidc_types::subject::Subject;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    session: SessionID,
    subject: Subject,
    auth_time: OffsetDateTime,
    max_age: u64,
}

impl AuthenticatedUser {
    pub fn new(
        session: SessionID,
        subject: Subject,
        auth_time: OffsetDateTime,
        max_age: u64,
    ) -> Self {
        Self {
            session,
            subject,
            auth_time,
            max_age,
        }
    }

    pub fn sub(&self) -> &Subject {
        &self.subject
    }
    pub fn session(&self) -> SessionID {
        self.session
    }
    pub fn auth_time(&self) -> OffsetDateTime {
        self.auth_time
    }
    pub fn max_age(&self) -> u64 {
        self.max_age
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SessionID(Uuid);

impl SessionID {
    pub fn new() -> Self {
        SessionID::default()
    }
}

impl FromStr for SessionID {
    type Err = UuidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let session_id = Uuid::from_str(s)?;
        Ok(SessionID(session_id))
    }
}
impl Default for SessionID {
    fn default() -> Self {
        SessionID(Uuid::new_v4())
    }
}

impl Display for SessionID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Identifiable<String> for AuthenticatedUser {
    fn id(&self) -> String {
        self.session.0.to_string()
    }
}
