use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::{Error as UuidError, Uuid};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SessionID(Uuid);

impl SessionID {
    pub fn new() -> Self {
        SessionID::default()
    }
}

impl TryFrom<Vec<u8>> for SessionID {
    type Error = uuid::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Uuid::from_slice(&value).map(SessionID)
    }
}

impl AsRef<[u8]> for SessionID {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
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
