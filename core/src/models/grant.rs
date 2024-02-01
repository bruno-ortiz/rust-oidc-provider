use std::collections::HashSet;
use std::fmt::{Display, Formatter};

use derive_builder::Builder;
use getset::{CopyGetters, Getters};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use oidc_types::acr::Acr;
use oidc_types::amr::Amr;
use oidc_types::claims::Claims;
use oidc_types::client::ClientID;
use oidc_types::identifiable::Identifiable;
use oidc_types::scopes::Scopes;
use oidc_types::subject::Subject;

use crate::adapter::PersistenceError;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::Status;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct GrantID(Uuid);

impl TryFrom<Vec<u8>> for GrantID {
    type Error = uuid::Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Uuid::from_slice(&value).map(GrantID)
    }
}

impl AsRef<[u8]> for GrantID {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Display for GrantID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Builder, Getters, CopyGetters)]
#[get = "pub"]
#[builder(setter(into))]
pub struct Grant {
    #[getset(skip)]
    #[get_copy = "pub"]
    #[builder(setter(custom))]
    id: GrantID,
    #[builder(setter(custom))]
    #[getset(skip)]
    #[get_copy = "pub"]
    status: Status,
    #[getset(skip)]
    #[get_copy = "pub"]
    client_id: ClientID,
    scopes: Option<Scopes>,
    subject: Subject,
    acr: Acr,
    amr: Option<Amr>,
    #[getset(skip)]
    #[get_copy = "pub"]
    auth_time: OffsetDateTime,
    claims: Option<Claims>,
    rejected_claims: HashSet<String>,
    max_age: Option<u64>,
    redirect_uri: Option<Url>,
}

impl Grant {
    pub async fn find(
        provider: &OpenIDProviderConfiguration,
        id: GrantID,
    ) -> Result<Option<Grant>, PersistenceError> {
        Ok(provider
            .adapter()
            .grant()
            .find(&id)
            .await?
            .filter(|it| it.status != Status::Consumed))
    }

    pub async fn save(
        self,
        provider: &OpenIDProviderConfiguration,
    ) -> Result<Self, PersistenceError> {
        provider.adapter().grant().insert(self, None).await
    }

    pub async fn update(
        self,
        provider: &OpenIDProviderConfiguration,
    ) -> Result<Self, PersistenceError> {
        provider.adapter().grant().update(self, None).await
    }

    pub async fn consume(
        mut self,
        provider: &OpenIDProviderConfiguration,
    ) -> Result<Grant, OpenIdError> {
        self.status = Status::Consumed;
        self.update(provider)
            .await
            .map_err(OpenIdError::server_error)
    }

    pub fn has_requested_scopes(&self, requested: &Scopes) -> bool {
        if let Some(ref scopes) = self.scopes {
            scopes.contains_all(requested)
        } else {
            false
        }
    }
}

impl GrantBuilder {
    pub fn new() -> Self {
        let mut builder = Self::create_empty();
        builder.id = Some(GrantID(Uuid::new_v4()));
        builder.status = Some(Status::Awaiting);
        builder
    }

    pub fn new_with(id: GrantID, status: Status) -> Self {
        let mut builder = Self::create_empty();
        builder.id = Some(id);
        builder.status = Some(status);
        builder
    }
}

impl Identifiable<GrantID> for Grant {
    fn id(&self) -> &GrantID {
        &self.id
    }
}
