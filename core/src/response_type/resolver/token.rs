use crate::access_token::AccessToken;
use crate::adapter::Adapter;
use crate::context::OpenIDContext;
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::ResponseTypeResolver;
use async_trait::async_trait;
use std::sync::Arc;
use time::Duration;
use uuid::Uuid;

pub struct TokenResolver {
    repository: Arc<dyn Adapter<Id = String, Item = AccessToken> + Send + Sync>,
}

impl TokenResolver {
    pub fn new(adapter: Arc<dyn Adapter<Id = String, Item = AccessToken> + Send + Sync>) -> Self {
        Self {
            repository: adapter,
        }
    }
}

#[async_trait]
impl ResponseTypeResolver for TokenResolver {
    type Output = AccessToken;

    async fn resolve(&self, _context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let token = AccessToken::new(
            Uuid::new_v4().to_string(),
            "Bearer".to_owned(),
            Duration::minutes(10),
            None,
        );
        let token = self
            .repository
            .save(token)
            .await
            .map_err(|err| OpenIdError::ServerError { source: err.into() })?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_can_create_access_token() {
        todo!()
    }
}
