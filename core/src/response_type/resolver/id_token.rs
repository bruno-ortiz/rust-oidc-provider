use anyhow::anyhow;
use async_trait::async_trait;
use tracing::error;

use oidc_types::code::Code;
use oidc_types::jose::Algorithm;
use oidc_types::response_type::Flow;
use oidc_types::simple_id_token::SimpleIdToken;

use crate::claims::get_id_token_claims;
use crate::configuration::clock::Clock;
use crate::context::OpenIDContext;
use crate::error::OpenIdError;
use crate::id_token_builder::IdTokenBuilder;
use crate::keystore::KeyUse;
use crate::models::access_token::AccessToken;
use crate::profile::ProfileData;
use crate::response_type::resolver::ResponseTypeResolver;
use crate::utils::resolve_sub;

pub struct IDTokenResolver<'a> {
    code: Option<&'a Code>,
    token: Option<&'a AccessToken>,
}

impl<'a> IDTokenResolver<'a> {
    pub fn new(code: Option<&'a Code>, token: Option<&'a AccessToken>) -> Self {
        IDTokenResolver { code, token }
    }
}

#[async_trait]
impl ResponseTypeResolver for IDTokenResolver<'_> {
    type Output = SimpleIdToken;

    async fn resolve(&self, context: &OpenIDContext) -> Result<Self::Output, OpenIdError> {
        let clock = context.provider.clock_provider();
        let client = context.client.clone();
        let client_metadata = client.metadata();
        let alg = &client_metadata.id_token_signed_response_alg;
        let keystore = context.keystore_service.server_keystore(&client, alg);
        let signing_key = keystore
            .select(Some(KeyUse::Sig))
            .alg(alg.name())
            .first()
            .ok_or_else(|| OpenIdError::server_error(anyhow!("Missing signing key")))?;
        let flow_type = context.flow_type();
        if (flow_type == Flow::Hybrid || flow_type == Flow::Implicit)
            && context.request.nonce.is_none()
        {
            return Err(OpenIdError::invalid_request(
                "Hybrid flow must contain a nonce in the auth request",
            ));
        }
        let profile = ProfileData::get(context.provider, &context.grant, &context.client)
            .await
            .map_err(OpenIdError::server_error)?;
        let claims = get_id_token_claims(
            &profile,
            context.grant.claims().as_ref(),
            context.grant.rejected_claims(),
        )?;

        let ttl = context.provider.ttl();

        let sub = resolve_sub(context.provider, context.user.sub(), &client)
            .map_err(OpenIdError::server_error)?;
        let mut id_token_builder = IdTokenBuilder::new(signing_key)
            .with_issuer(context.provider.issuer())
            .with_sub(&sub)
            .with_audience(vec![context.client.id().into()])
            .with_exp(clock.now() + ttl.id_token)
            .with_iat(clock.now())
            .with_nonce(context.request.nonce.as_ref())
            .with_s_hash(context.request.state.as_ref())?
            .with_c_hash(self.code)?
            .with_at_hash(self.token)?
            .with_custom_claims(claims);

        if context.request.max_age.is_some() {
            id_token_builder = id_token_builder.with_auth_time(context.user.auth_time())
        }

        let id_token = id_token_builder.build().map_err(|err| {
            error!("{:?}", err);
            OpenIdError::server_error(err)
        })?;

        id_token
            .return_or_encrypt_simple_id_token(&context.keystore_service, &context.client)
            .await
            .map_err(OpenIdError::server_error)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use oidc_types::issuer::Issuer;
    use oidc_types::jose::jwt2::{SignedJWT, JWT};
    use oidc_types::nonce::Nonce;
    use oidc_types::response_type;
    use oidc_types::response_type::ResponseTypeValue;
    use oidc_types::state::State;
    use oidc_types::subject::Subject;

    use crate::context::test_utils::{setup_context, setup_provider};
    use crate::error::OpenIdErrorType;
    use crate::hash::TokenHasher;
    use crate::services::keystore::KeystoreService;

    use super::*;

    #[tokio::test]
    async fn can_generate_id_token() {
        let state = State::new("mock-state");
        let nonce = Nonce::new("some-nonce");
        let provider = Arc::new(setup_provider());
        let keystore_service = Arc::new(KeystoreService::new(provider.clone()));
        let context = setup_context(
            &provider,
            keystore_service,
            response_type![ResponseTypeValue::Code],
            Some(state.clone()),
            Some(nonce.clone()),
        )
        .await;
        let keystore = context.provider.keystore();
        let signing_key = keystore.select(Some(KeyUse::Sig)).first().unwrap();
        let resolver = IDTokenResolver::new(None, None);

        let id_token = resolver
            .resolve(&context)
            .await
            .expect("Expecting a id token");

        let id_token = SignedJWT::decode_no_verify(id_token).unwrap();

        let payload = id_token.payload();
        assert_eq!(
            context.user.sub(),
            &payload.subject().map(Subject::new).unwrap()
        );
        assert_eq!(
            context.provider.issuer(),
            &payload.issuer().map(Issuer::new).unwrap()
        );
        assert_eq!(
            vec![context.client.id().to_string().as_str()],
            payload.audience().unwrap()
        );
        assert_eq!(
            nonce,
            payload
                .claim("nonce")
                .map(|n| Nonce::new(n.as_str().unwrap()))
                .unwrap()
        );
        assert!(payload.expires_at().is_some());
        assert!(payload.issued_at().is_some());
        assert_eq!(
            state.hash(signing_key).unwrap(),
            payload
                .claim("s_hash")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        );
        assert!(payload.claim("c_hash").is_none());
        assert!(payload.claim("at_hash").is_none());
    }

    #[tokio::test]
    async fn nonce_is_required_when_hybrid_flow() {
        let state = State::new("mock-state");
        let provider = Arc::new(setup_provider());
        let keystore_service = Arc::new(KeystoreService::new(provider.clone()));
        let context = setup_context(
            &provider,
            keystore_service,
            response_type![ResponseTypeValue::Code, ResponseTypeValue::IdToken],
            Some(state.clone()),
            None,
        )
        .await;
        let resolver = IDTokenResolver::new(None, None);
        let result = resolver.resolve(&context).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().error_type(),
            OpenIdErrorType::InvalidRequest
        )
    }
}
