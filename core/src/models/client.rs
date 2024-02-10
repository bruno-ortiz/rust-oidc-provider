use std::ops::Deref;

use getset::{CopyGetters, Getters};
use time::OffsetDateTime;

use oidc_types::auth_method::AuthMethod;
use oidc_types::client::{ClientID, ClientMetadata};
use oidc_types::grant_type::GrantType;
use oidc_types::identifiable::Identifiable;
use oidc_types::jose::jws::SigningAlgorithm;
use oidc_types::secret::{HashedSecret, PlainTextSecret};

#[derive(Debug, Clone, CopyGetters, Getters)]
pub struct ClientInformation {
    #[get_copy = "pub"]
    id: ClientID,
    #[get_copy = "pub"]
    issue_date: OffsetDateTime,
    #[get = "pub"]
    secret: PlainTextSecret, // This needs to be plaintext because of the symmetric key creation, should encrypt this in the database
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

    pub fn encrypt_id_token(&self) -> bool {
        self.metadata.id_token_encryption_data().is_some()
    }
}

impl Identifiable<ClientID> for ClientInformation {
    fn id(&self) -> &ClientID {
        &self.id
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
    pub fn id_token_signing_alg(&self) -> &SigningAlgorithm {
        &self.0.metadata.id_token_signed_response_alg
    }
}

impl Deref for AuthenticatedClient {
    type Target = ClientInformation;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<ClientInformation> for AuthenticatedClient {
    fn as_ref(&self) -> &ClientInformation {
        &self.0
    }
}
