use serde::Serialize;
use std::fmt::{Display, Formatter};
use time::Duration;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct RefreshToken {
    token: String,
    #[serde(skip)]
    duration: Duration,
}

impl Display for RefreshToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.token)
    }
}
