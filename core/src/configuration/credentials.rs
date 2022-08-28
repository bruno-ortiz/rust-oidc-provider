use oidc_types::scopes::Scopes;
use time::Duration;

const DEFAULT_DURATION: i64 = 10;

#[derive(Debug, Clone)]
pub struct ClientCredentialConfiguration {
    pub duration: Duration,
    pub allowed_scopes: Option<Scopes>,
}

impl ClientCredentialConfiguration {
    pub fn new(duration: Duration, allowed_scopes: Option<Scopes>) -> Self {
        Self {
            duration,
            allowed_scopes,
        }
    }
}

impl Default for ClientCredentialConfiguration {
    fn default() -> Self {
        Self::new(Duration::minutes(DEFAULT_DURATION), None)
    }
}
