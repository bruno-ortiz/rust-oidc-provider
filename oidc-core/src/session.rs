use std::str::FromStr;

use uuid::{Error as UuidError, Uuid};

use oidc_types::subject::Subject;

#[derive(Debug)]
pub struct AuthenticatedUser {
    session: SessionID,
    subject: Subject,
}

impl AuthenticatedUser {
    pub fn sub(&self) -> &Subject {
        &self.subject
    }
}

#[derive(Debug)]
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
