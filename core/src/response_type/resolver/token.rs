use async_trait::async_trait;

use crate::configuration::OpenIDProviderConfiguration;
use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::models::access_token::AccessToken;
use crate::response_type::resolver::ResponseTypeResolver;

pub struct TokenResolver;
#[async_trait]
impl ResponseTypeResolver for TokenResolver {
    type Output = AccessToken;

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let configuration = OpenIDProviderConfiguration::instance();
        let ttl = configuration.ttl();
        let at_ttl = ttl.access_token_ttl(context.client.as_ref());
        let token = AccessToken::bearer(at_ttl, Some(context.request.scope.clone()));
        let token = configuration
            .adapters()
            .token()
            .save(token)
            .await
            .map_err(|err| OpenIdError::server_error(err.into()))?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use crate::configuration::OpenIDProviderConfiguration;
    use oidc_types::identifiable::Identifiable;
    use oidc_types::response_type;
    use oidc_types::response_type::ResponseTypeValue;

    use crate::context::test_utils::setup_context;
    use crate::response_type::resolver::token::TokenResolver;
    use crate::response_type::resolver::ResponseTypeResolver;

    #[tokio::test]
    async fn test_can_create_access_token() {
        let context = setup_context(response_type!(ResponseTypeValue::Token), None, None);

        let resolver = TokenResolver;

        let configuration = OpenIDProviderConfiguration::instance();
        let token = resolver.resolve(&context).await.expect("Should be Ok()");
        let new_token = configuration.adapters().token().find(&token.id()).await;

        assert!(new_token.is_some());
        assert_eq!(token, new_token.unwrap());
    }
}
