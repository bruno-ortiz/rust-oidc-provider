use crate::configuration::clock::Clock;
use async_trait::async_trait;

use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::models::access_token::AccessToken;
use crate::response_type::resolver::ResponseTypeResolver;

pub struct TokenResolver;
#[async_trait]
impl ResponseTypeResolver for TokenResolver {
    type Output = AccessToken;

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let ttl = context.provider.ttl();
        let at_ttl = ttl.access_token_ttl(context.client.as_ref());
        let clock = context.provider.clock_provider();
        let token = AccessToken::bearer(
            clock.now(),
            context.grant.id(),
            at_ttl,
            Some(context.request.scope.clone()),
        );
        let token = context
            .provider
            .adapter()
            .token()
            .insert(token, None)
            .await
            .map_err(OpenIdError::server_error)?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use oidc_types::identifiable::Identifiable;
    use oidc_types::response_type;
    use oidc_types::response_type::ResponseTypeValue;

    use crate::context::test_utils::{setup_context, setup_provider};
    use crate::response_type::resolver::token::TokenResolver;
    use crate::response_type::resolver::ResponseTypeResolver;

    #[tokio::test]
    async fn test_can_create_access_token() {
        let provider = setup_provider();
        let context = setup_context(
            &provider,
            response_type!(ResponseTypeValue::Token),
            None,
            None,
        )
        .await;

        let resolver = TokenResolver;

        let token = resolver.resolve(&context).await.expect("Should be Ok()");
        let new_token = provider.adapter().token().find(token.id()).await.unwrap();

        assert!(new_token.is_some());
        assert_eq!(token, new_token.unwrap());
    }
}
