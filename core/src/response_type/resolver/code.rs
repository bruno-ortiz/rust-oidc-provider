use anyhow::anyhow;
use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::models::authorisation_code::{AuthorisationCode, CodeStatus};
use crate::response_type::resolver::ResponseTypeResolver;

pub(crate) struct CodeResolver;

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
            status: CodeStatus::Awaiting,
            expires_in: OffsetDateTime::now_utc() + ttl.authorization_code,
            redirect_uri: authorisation_request.redirect_uri.clone(),
            subject: context.user.sub().clone(),
            scope: grant.scopes().clone(),
            nonce: context.request.nonce.clone(),
            state: context.request.state.clone(),
        };
        let code = context
            .configuration
            .adapters()
            .code()
            .save(code)
            .await
            .map_err(|err| OpenIdError::server_error(err.into()))?;
        return Ok(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::test_utils::setup_context;
    use oidc_types::response_type;
    use oidc_types::response_type::ResponseTypeValue;

    #[tokio::test]
    async fn can_generate_authorisation_code() {
        let context = setup_context(response_type![ResponseTypeValue::Code], None, None);
        let resolver = CodeResolver;

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
        let resolver = CodeResolver;

        let code = resolver
            .resolve(&context)
            .await
            .expect("Expecting a auth code");

        let saved_code = context
            .configuration
            .adapters()
            .code()
            .find(&code.code)
            .await
            .expect("Expected authorisation code to be saved");

        assert_eq!(code, saved_code)
    }
}
