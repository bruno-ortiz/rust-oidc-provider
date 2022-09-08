use std::fmt::{Display, Formatter};

use derive_builder::Builder;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::client::ClientID;
use oidc_types::identifiable::Identifiable;
use oidc_types::nonce::Nonce;
use oidc_types::scopes::Scopes;
use oidc_types::state::State;
use oidc_types::subject::Subject;

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;

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

impl RefreshToken {
    pub async fn save(
        self,
        config: &OpenIDProviderConfiguration,
    ) -> Result<RefreshToken, PersistenceError> {
        config.adapters().refresh().save(self).await
    }
}

impl Identifiable<String> for RefreshToken {
    fn id(&self) -> String {
        self.token.to_string()
    }
}

impl Display for RefreshToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.token)
    }
}
