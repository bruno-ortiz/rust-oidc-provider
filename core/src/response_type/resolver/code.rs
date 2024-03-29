use async_trait::async_trait;

use oidc_types::code::Code;

use crate::configuration::clock::Clock;
use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::models::authorisation_code::AuthorisationCode;
use crate::models::Status;
use crate::response_type::resolver::ResponseTypeResolver;

pub(crate) struct CodeResolver;

#[async_trait]
impl ResponseTypeResolver for CodeResolver {
    type Output = Code;

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let authorisation_request = &context.request;

        let clock = context.provider.clock_provider();
        let ttl = context.provider.ttl();
        let code = AuthorisationCode {
            id: None,
            code: Code::random(),
            grant_id: context.grant.id(),
            code_challenge: authorisation_request.code_challenge.clone(),
            code_challenge_method: authorisation_request.code_challenge_method,
            status: Status::Awaiting,
            expires_in: clock.now() + ttl.authorization_code,
            state: context.request.state.clone(),
            nonce: context.request.nonce.clone(),
            scopes: context.request.scope.clone(),
        };
        let code = context
            .provider
            .adapter()
            .code()
            .insert(code, context.txn_id.clone_some())
            .await
            .map_err(OpenIdError::server_error)?;
        return Ok(code.code);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use oidc_types::response_type;
    use oidc_types::response_type::ResponseTypeValue;

    use crate::context::test_utils::{setup_context, setup_provider};
    use crate::models::Status;
    use crate::services::keystore::KeystoreService;

    use super::*;

    #[tokio::test]
    async fn can_generate_authorisation_code() {
        let provider = Arc::new(setup_provider());
        let keystore_service = Arc::new(KeystoreService::new(provider.clone()));
        let context = setup_context(
            &provider,
            keystore_service,
            response_type![ResponseTypeValue::Code],
            None,
            None,
        )
        .await;
        let resolver = CodeResolver;
        let code = resolver
            .resolve(&context)
            .await
            .expect("Expecting a auth code");

        let code = provider
            .adapter()
            .code()
            .find(&code)
            .await
            .expect("Error saving code")
            .expect("Expected code");

        let grant = provider
            .adapter()
            .grant()
            .find(&code.grant_id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(context.user.sub(), grant.subject());
        assert_eq!(context.request.code_challenge, code.code_challenge);
        assert_eq!(
            context.request.code_challenge_method.unwrap(),
            code.code_challenge_method.unwrap()
        );
        assert_eq!(context.client.id(), grant.client_id());
        assert_eq!(Some(context.request.scope), *grant.scopes());
        assert_eq!(Status::Awaiting, code.status);
        assert_eq!(Some(context.request.redirect_uri), *grant.redirect_uri());
    }

    #[tokio::test]
    async fn can_find_authorisation_code() {
        let provider = Arc::new(setup_provider());
        let keystore_service = Arc::new(KeystoreService::new(provider.clone()));
        let context = setup_context(
            &provider,
            keystore_service,
            response_type![ResponseTypeValue::Code],
            None,
            None,
        )
        .await;
        let resolver = CodeResolver;
        let code = resolver
            .resolve(&context)
            .await
            .expect("Expecting a auth code");

        provider
            .adapter()
            .code()
            .find(&code)
            .await
            .expect("Expected authorisation code to be saved");
    }
}
