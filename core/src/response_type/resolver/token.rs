use crate::adapter::Adapter;
use crate::context::OpenIDContext;
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::ResponseTypeResolver;
use async_trait::async_trait;
use oidc_types::access_token::AccessToken;
use std::sync::Arc;
use time::Duration;

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

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let token = AccessToken::new(
            "Bearer".to_owned(),
            Duration::minutes(10),
            None,
            Some(context.request.scope.clone()),
        );
        let token = self
            .repository
            .save(token)
            .await
            .map_err(|err| OpenIdError::server_error(err.into()))?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use crate::adapter::generic_adapter::InMemoryGenericAdapter;
    use crate::adapter::Adapter;
    use crate::context::test_utils::setup_context;
    use crate::response_type::resolver::token::TokenResolver;
    use crate::response_type::resolver::ResponseTypeResolver;
    use oidc_types::identifiable::Identifiable;
    use oidc_types::response_type;
    use oidc_types::response_type::ResponseTypeValue;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_can_create_access_token() {
        let context = setup_context(response_type!(ResponseTypeValue::Token), None, None);
        let adapter = Arc::new(InMemoryGenericAdapter::new());

        let resolver = TokenResolver::new(adapter.clone());

        let token = resolver.resolve(&context).await.expect("Should be Ok()");

        let new_token = adapter.find(&token.id()).await;

        assert!(new_token.is_some());
        assert_eq!(token, new_token.unwrap());
    }
}
