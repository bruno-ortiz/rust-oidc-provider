use crate::adapter::Adapter;
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use crate::authorisation_code::{AuthorisationCode, CodeStatus};
use crate::context::OpenIDContext;
use crate::response_type::errors::OpenIdError;
use crate::response_type::resolver::ResponseTypeResolver;

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
        let code = AuthorisationCode {
            code: Uuid::new_v4().to_string(),
            client_id: context.client.id,
            code_challenge: authorisation_request.code_challenge.clone(),
            code_challenge_method: authorisation_request.code_challenge_method.clone(),
            scope: authorisation_request.scope.clone(),
            redirect_uri: authorisation_request.redirect_uri.clone(),
            status: CodeStatus::Awaiting,
            subject: context.user.sub().clone(),
        };
        let code = self
            .adapter
            .save(code)
            .await
            .map_err(|err| OpenIdError::ServerError { source: err.into() })?;
        return Ok(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::code_adapter::InMemoryAuthorisationCodeAdapter;
    use crate::authorisation_request::ValidatedAuthorisationRequest;
    use crate::configuration::OpenIDProviderConfiguration;
    use crate::session::{AuthenticatedUser, SessionID};
    use oidc_types::client::{ClientID, ClientInformation, ClientMetadata};
    use oidc_types::pkce::{CodeChallenge, CodeChallengeMethod};
    use oidc_types::response_type::ResponseTypeValue;
    use oidc_types::subject::Subject;
    use oidc_types::{response_type, scopes};
    use time::OffsetDateTime;
    use url::Url;

    #[tokio::test]
    async fn can_generate_authorisation_code() {
        let context = setup_context();
        let resolver = CodeResolver::new(Arc::new(InMemoryAuthorisationCodeAdapter::new()));

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
        let context = setup_context();
        let adapter = Arc::new(InMemoryAuthorisationCodeAdapter::new());
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

    //noinspection DuplicatedCode
    fn setup_context() -> OpenIDContext {
        let client_id = ClientID::new(Uuid::new_v4());
        let request = ValidatedAuthorisationRequest {
            client_id,
            response_type: response_type![ResponseTypeValue::Code],
            redirect_uri: Url::parse("https://test.com/callback").unwrap(),
            scope: scopes!("openid", "test"),
            state: None,
            response_mode: None,
            code_challenge: Some(CodeChallenge::new("some code here")),
            code_challenge_method: Some(CodeChallengeMethod::Plain),
            resource: None,
            include_granted_scopes: None,
            request_uri: None,
            request: None,
            prompt: None,
        };
        let client = ClientInformation {
            id: client_id,
            issue_date: OffsetDateTime::now_utc(),
            metadata: ClientMetadata {
                redirect_uris: vec![],
                token_endpoint_auth_method: None,
                grant_types: vec![],
                response_types: vec![],
                scope: scopes!("openid", "test"),
                client_name: None,
                client_uri: None,
                logo_uri: None,
                tos_uri: None,
                policy_uri: None,
                contacts: vec![],
                jwks_uri: None,
                jwks: None,
                software_id: None,
                software_version: None,
                software_statement: None,
            },
        };

        let user = AuthenticatedUser::new(
            SessionID::default(),
            Subject::new("some-id"),
            OffsetDateTime::now_utc(),
            120,
        );

        let config = OpenIDProviderConfiguration::default();
        OpenIDContext::new(Arc::new(client), user, request, Arc::new(config))
    }
}
