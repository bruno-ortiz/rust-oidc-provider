use getset::{CopyGetters, Getters};
use time::OffsetDateTime;

use oidc_types::auth_method::AuthMethod;
use oidc_types::client::{ClientID, ClientMetadata};
use oidc_types::grant_type::GrantType;
use oidc_types::identifiable::Identifiable;
use oidc_types::secret::PlainTextSecret;

#[derive(Debug, Clone, CopyGetters, Getters)]
pub struct ClientInformation {
    #[get_copy = "pub"]
    id: ClientID,
    #[get_copy = "pub"]
    issue_date: OffsetDateTime,
    #[get = "pub"]
    secret: PlainTextSecret,
    #[get_copy = "pub"]
    secret_expires_at: Option<OffsetDateTime>,
    #[get = "pub"]
    metadata: ClientMetadata,
}

impl ClientInformation {
    pub fn new(
        id: ClientID,
        issue_date: OffsetDateTime,
        secret: PlainTextSecret,
        secret_expires_at: Option<OffsetDateTime>,
        metadata: ClientMetadata,
    ) -> Self {
        Self {
            id,
            issue_date,
            secret,
            secret_expires_at,
            metadata,
        }
    }

    pub fn consume_metadata(self) -> ClientMetadata {
        self.metadata
    }
}

impl Identifiable<ClientID> for ClientInformation {
    fn id(&self) -> ClientID {
        self.id
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedClient(ClientInformation);

impl AuthenticatedClient {
    pub fn new(client: ClientInformation) -> Self {
        Self(client)
    }

    pub fn id(&self) -> ClientID {
        self.0.id
    }

    pub fn allows_grant(&self, grant_type: GrantType) -> bool {
        self.0.metadata.grant_types.contains(&grant_type)
    }
    pub fn auth_method(&self) -> AuthMethod {
        self.0.metadata.token_endpoint_auth_method
    }
}

impl AsRef<ClientInformation> for AuthenticatedClient {
    fn as_ref(&self) -> &ClientInformation {
        &self.0
    }
}
