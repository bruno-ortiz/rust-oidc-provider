use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::claims::Claims;
use oidc_types::nonce::Nonce;
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;

pub mod access_token;
pub(crate) mod authorisation_code;
pub mod client;
pub(crate) mod refresh_token;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Status {
    Awaiting,
    Consumed,
}

impl Default for Status {
    fn default() -> Self {
        Self::Awaiting
    }
}

pub trait Token {
    fn subject(&self) -> &Subject;
    fn auth_time(&self) -> u64;
    fn acr(&self) -> &Acr;
    fn amr(&self) -> Option<&Amr>;
    fn scopes(&self) -> &Scopes;
    fn claims(&self) -> Option<&Claims>;
    fn nonce(&self) -> Option<&Nonce>;
}
