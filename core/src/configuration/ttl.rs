use futures::future::BoxFuture;
use oidc_types::client::AuthenticatedClient;
use time::Duration;

//todo: allow generic params to be passed to this function
// this can allow the duration to be parameterized with a consent duration for example;
type TTLResolver = Box<dyn Fn() -> Duration + Send + Sync>;
type AsyncTTLResolver = Box<dyn Fn(&AuthenticatedClient) -> BoxFuture<Duration> + Send + Sync>;

pub struct TTL {
    pub access_token: TTLResolver,
    pub refresh_token: AsyncTTLResolver,
    pub client_credentials: TTLResolver,
    pub authorization_code: Duration,
}

impl TTL {
    pub async fn refresh_token_ttl(&self, client: &AuthenticatedClient) -> Duration {
        let func = &self.refresh_token;
        func(client).await
    }
}

impl Default for TTL {
    fn default() -> Self {
        Self {
            access_token: Box::new(|| Duration::hours(1)),
            refresh_token: Box::new(|_client| Box::pin(async { Duration::days(14) })),
            client_credentials: Box::new(|| Duration::minutes(10)),
            authorization_code: Duration::minutes(10),
        }
    }
}
