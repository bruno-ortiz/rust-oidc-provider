use std::fmt::{Display, Formatter};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::{Error as UuidError, Uuid};

use oidc_types::subject::Subject;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    session: SessionID,
    subject: Subject,
    auth_time: DateTime<Utc>,
    max_age: u64,
}

impl AuthenticatedUser {
    pub fn sub(&self) -> &Subject {
        &self.subject
    }
    pub fn session(&self) -> &SessionID {
        &self.session
    }
    pub fn auth_time(&self) -> &SessionID {
        &self.session
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionID(Uuid);

impl SessionID {
    pub fn new() -> Self {
        SessionID::default()
    }

    pub fn from_string(id: String) -> Result<Self, UuidError> {
        let session_id = Uuid::from_str(&id)?;
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
