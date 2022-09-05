use crate::adapter::Adapter;
use anyhow::anyhow;
use async_trait::async_trait;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::response_type::resolver::ResponseTypeResolver;
use oidc_types::authorisation_code::{AuthorisationCode, CodeStatus};

pub(crate) struct CodeResolver {
    adapter: Arc<dyn Adapter<Item = AuthorisationCode, Id = String> + Send + Sync>,
}

impl CodeResolver {
    pub fn new(
        adapter: Arc<dyn Adapter<Item = AuthorisationCode, Id = String> + Send + Sync>,
    ) -> Self {
        Self { adapter }
    }
}

#[async_trait]
impl ResponseTypeResolver for CodeResolver {
    type Output = AuthorisationCode;

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let authorisation_request = &context.request;
        let grant = context.user.grant().ok_or_else(|| {
            OpenIdError::server_error(anyhow!("Trying to authorise user with no grant"))
        })?;
        let ttl = context.configuration.ttl();
        let code = AuthorisationCode {
            code: Uuid::new_v4().to_string(),
            client_id: context.client.id,
            code_challenge: authorisation_request.code_challenge.clone(),
            code_challenge_method: authorisation_request.code_challenge_method,
            scope: grant.scopes().clone(),
            redirect_uri: authorisation_request.redirect_uri.clone(),
            status: CodeStatus::Awaiting,
            subject: context.user.sub().clone(),
            expires_in: OffsetDateTime::now_utc() + ttl.authorization_code,
        };
        let code = self
            .adapter
            .save(code)
            .await
            .map_err(|err| OpenIdError::server_error(err.into()))?;
        return Ok(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::generic_adapter::InMemoryGenericAdapter;
    use crate::context::test_utils::setup_context;
    use oidc_types::response_type;
    use oidc_types::response_type::ResponseTypeValue;

    #[tokio::test]
    async fn can_generate_authorisation_code() {
        let context = setup_context(response_type![ResponseTypeValue::Code], None, None);
        let resolver = CodeResolver::new(Arc::new(InMemoryGenericAdapter::new()));

        let code = resolver
            .resolve(&context)
            .await
            .expect("Expecting a auth code");

        assert_eq!(context.user.sub(), &code.subject);
        assert_eq!(context.request.code_challenge, code.code_challenge);
        assert_eq!(
            context.request.code_challenge_method.unwrap(),
            code.code_challenge_method.unwrap()
        );
        assert_eq!(context.client.id, code.client_id);
        assert_eq!(context.request.scope, code.scope);
        assert_eq!(CodeStatus::Awaiting, code.status);
        assert_eq!(context.request.redirect_uri, code.redirect_uri);
    }

    #[tokio::test]
    async fn can_find_authorisation_code() {
        let context = setup_context(response_type![ResponseTypeValue::Code], None, None);
        let adapter = Arc::new(InMemoryGenericAdapter::new());
        let resolver = CodeResolver::new(adapter.clone());

        let code = resolver
            .resolve(&context)
            .await
            .expect("Expecting a auth code");

        let saved_code = adapter
            .find(&code.code)
            .await
            .expect("Expected authorisation code to be saved");

        assert_eq!(code, saved_code)
    }
}
