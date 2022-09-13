use futures::future::BoxFuture;
use time::Duration;

use crate::models::client::{AuthenticatedClient, ClientInformation};

//todo: allow generic params to be passed to this function
// this can allow the duration to be parameterized with a consent duration for example;
type TTLResolver = Box<dyn Fn(&ClientInformation) -> Duration + Send + Sync>;
type AsyncTTLResolver = Box<dyn Fn(&AuthenticatedClient) -> BoxFuture<Duration> + Send + Sync>;

pub struct TTL {
    pub access_token: TTLResolver,
    pub refresh_token: AsyncTTLResolver,
    pub client_credentials: TTLResolver,
    pub authorization_code: Duration,
    pub id_token: Duration,
}

impl TTL {
    pub async fn refresh_token_ttl(&self, client: &AuthenticatedClient) -> Duration {
        let func = &self.refresh_token;
        func(client).await
    }

    pub fn access_token_ttl(&self, client: &ClientInformation) -> Duration {
        let func = &self.access_token;
        func(client)
    }

    pub fn client_credentials_ttl(&self, client: &ClientInformation) -> Duration {
        let func = &self.client_credentials;
        func(client)
    }
}

impl Default for TTL {
    fn default() -> Self {
        Self {
            access_token: Box::new(|_client| Duration::hours(1)),
            refresh_token: Box::new(|_client| Box::pin(async { Duration::days(14) })),
            client_credentials: Box::new(|_client| Duration::minutes(10)),
            authorization_code: Duration::minutes(10),
            id_token: Duration::hours(1),
        }
    }
}
