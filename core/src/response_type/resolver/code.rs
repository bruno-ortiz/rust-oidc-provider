use anyhow::anyhow;
use async_trait::async_trait;
use time::OffsetDateTime;

use oidc_types::code::Code;

use crate::configuration::OpenIDProviderConfiguration;
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
        let grant = context.user.grant().ok_or_else(|| {
            OpenIdError::server_error(anyhow!("Trying to authorise user with no grant"))
        })?;
        let configuration = OpenIDProviderConfiguration::instance();
        let ttl = configuration.ttl();
        let code = AuthorisationCode {
            code: Code::random(),
            client_id: context.client.id(),
            code_challenge: authorisation_request.code_challenge.clone(),
            code_challenge_method: authorisation_request.code_challenge_method,
            status: Status::Awaiting,
            expires_in: OffsetDateTime::now_utc() + ttl.authorization_code,
            redirect_uri: authorisation_request.redirect_uri.clone(),
            subject: context.user.sub().clone(),
            scopes: grant.scopes().clone(),
            nonce: context.request.nonce.clone(),
            state: context.request.state.clone(),
            acr: context.user.acr().clone(),
            amr: context.user.amr().cloned(),
            auth_time: context.user.auth_time(),
        };
        let code = configuration
            .adapters()
            .code()
            .save(code)
            .await
            .map_err(|err| OpenIdError::server_error(err.into()))?;
        return Ok(code.code);
    }
}

#[cfg(test)]
mod tests {
    use oidc_types::response_type;
    use oidc_types::response_type::ResponseTypeValue;

    use crate::context::test_utils::setup_context;
    use crate::models::Status;

    use super::*;

    #[tokio::test]
    async fn can_generate_authorisation_code() {
        let context = setup_context(response_type![ResponseTypeValue::Code], None, None);
        let resolver = CodeResolver;
        let configuration = OpenIDProviderConfiguration::instance();
        let code = resolver
            .resolve(&context)
            .await
            .expect("Expecting a auth code");

        let code = configuration
            .adapters()
            .code()
            .find(&code)
            .await
            .expect("saved code");

        assert_eq!(context.user.sub(), &code.subject);
        assert_eq!(context.request.code_challenge, code.code_challenge);
        assert_eq!(
            context.request.code_challenge_method.unwrap(),
            code.code_challenge_method.unwrap()
        );
        assert_eq!(context.client.id(), code.client_id);
        assert_eq!(context.request.scope, code.scopes);
        assert_eq!(Status::Awaiting, code.status);
        assert_eq!(context.request.redirect_uri, code.redirect_uri);
    }

    #[tokio::test]
    async fn can_find_authorisation_code() {
        let context = setup_context(response_type![ResponseTypeValue::Code], None, None);
        let resolver = CodeResolver;
        let configuration = OpenIDProviderConfiguration::instance();
        let code = resolver
            .resolve(&context)
            .await
            .expect("Expecting a auth code");

        configuration
            .adapters()
            .code()
            .find(&code)
            .await
            .expect("Expected authorisation code to be saved");
    }
}
