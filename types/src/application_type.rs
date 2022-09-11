use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationType {
    Native,
    Web,
}

impl Display for ApplicationType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplicationType::Native => write!(f, "native"),
            ApplicationType::Web => write!(f, "web"),
        }
    }
}
