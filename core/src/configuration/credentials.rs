use oidc_types::scopes::Scopes;
use time::Duration;

#[derive(Debug, Clone)]
pub struct ClientCredentialConfiguration {
    pub allowed_scopes: Option<Scopes>,
}

impl ClientCredentialConfiguration {
    pub fn new(allowed_scopes: Option<Scopes>) -> Self {
        Self { allowed_scopes }
    }
}

impl Default for ClientCredentialConfiguration {
    fn default() -> Self {
        Self::new(None)
    }
}
