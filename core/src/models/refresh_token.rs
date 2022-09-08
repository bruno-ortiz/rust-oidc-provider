use std::fmt::{Display, Formatter};

use derive_builder::Builder;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::client::ClientID;
use oidc_types::nonce::Nonce;
use oidc_types::scopes::Scopes;
use oidc_types::state::State;
use oidc_types::subject::Subject;

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
#[builder(setter(into))]
pub struct RefreshToken {
    pub token: Uuid,
    pub client_id: ClientID,
    pub subject: Subject,
    pub redirect_uri: Url,
    pub scope: Scopes,
    pub expires_in: OffsetDateTime,
    pub created: OffsetDateTime,
    pub acr: Acr,
    pub nonce: Option<Nonce>,
    pub state: Option<State>,
    pub amr: Option<Amr>,
}

impl Display for RefreshToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.token)
    }
}
