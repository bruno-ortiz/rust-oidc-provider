use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use oidc_core::services::introspect_service::IntrospectionService;
use oidc_types::introspection::{IntrospectionRequestBody, IntrospectionResponse};

use crate::authenticated_request::AuthenticatedRequest;
use crate::routes::error::OpenIdErrorResponse;

//#[axum_macros::debug_handler]
pub async fn introspect(
    State(service): State<Arc<IntrospectionService>>,
    request: AuthenticatedRequest<IntrospectionRequestBody>,
) -> axum::response::Result<Json<IntrospectionResponse>, OpenIdErrorResponse> {
    let introspection_response = service
        .introspect(request.body, request.authenticated_client)
        .await
        .map_err(OpenIdErrorResponse::from)?;
    Ok(Json(introspection_response))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::{str::FromStr, sync::Arc};

    use axum::body::Body;
    use axum::http::Request;
    use axum_extra::headers::authorization::Credentials;
    use axum_extra::headers::{authorization::Basic, Authorization};
    use hyper::header::AUTHORIZATION;
    use hyper::Method;
    use mockall::mock;
    use oidc_core::configuration::adapter_container::DefaultAdapterContainerBuilder;
    use oidc_core::models::access_token::AccessToken;
    use oidc_core::models::grant::{Grant, GrantBuilder, GrantID};
    use oidc_core::models::refresh_token::{RefreshToken, RefreshTokenBuilder};
    use oidc_core::{
        client::register_client,
        configuration::{OpenIDProviderConfiguration, OpenIDProviderConfigurationBuilder},
        models::client::ClientInformation,
    };
    use oidc_types::acr::Acr;
    use oidc_types::claims::Claims;
    use oidc_types::introspection::IntrospectionResponse;
    use oidc_types::subject::Subject;
    use oidc_types::{
        auth_method::AuthMethod,
        client::{ClientID, ClientMetadataBuilder},
        grant_type::GrantType,
        jose::{alg::ecdsa::EcdsaJwsAlgorithm, jwk_set::JwkSet},
        response_type::ResponseTypeValue,
        scopes,
        secret::PlainTextSecret,
    };
    use time::{Duration, OffsetDateTime};
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::routes::oidc_router;
    use http_body_util::BodyExt;
    use oidc_core::adapter::{Adapter, PersistenceError};

    use oidc_core::persistence::TransactionId;

    const CLIENT_NAME: &str = "Test Client";
    const CLIENT_ID: &str = "1d8fca3b-a2f1-48c2-924d-843e5173a951";
    const CLIENT_SECRET: &str = "1fCW^$)*(I#tll2EH#!MfsHFQ$*6&gEx";
    const AUTH_METHOD: AuthMethod = AuthMethod::ClientSecretBasic;

    mock! {
        pub TokenAdapter {}
        #[async_trait::async_trait]
        impl Adapter for TokenAdapter {
            type Id=Uuid;
            type Item=AccessToken;

            async fn find(&self, id: &Uuid) -> Result<Option<AccessToken>, PersistenceError>;

            async fn insert(
                &self,
                item: AccessToken,
                active_txn: Option<TransactionId>,
            ) -> Result<AccessToken, PersistenceError>;

            async fn update(
                &self,
                item: AccessToken,
                active_txn: Option<TransactionId>,
            ) -> Result<AccessToken, PersistenceError>;

        }
    }
    mock! {
        pub RTAdapter {}
        #[async_trait::async_trait]
        impl Adapter for RTAdapter {
            type Id=Uuid;
            type Item=RefreshToken;

            async fn find(&self, id: &Uuid) -> Result<Option<RefreshToken>, PersistenceError>;

            async fn insert(
                &self,
                item: RefreshToken,
                active_txn: Option<TransactionId>,
            ) -> Result<RefreshToken, PersistenceError>;

            async fn update(
                &self,
                item: RefreshToken,
                active_txn: Option<TransactionId>,
            ) -> Result<RefreshToken, PersistenceError>;

        }
    }

    mock! {
        pub GrantAdapter {}
        #[async_trait::async_trait]
        impl Adapter for GrantAdapter {
            type Id=GrantID;
            type Item=Grant;

            async fn find(&self, id: &GrantID) -> Result<Option<Grant>, PersistenceError>;

            async fn insert(
                &self,
                    item: Grant,
                    active_txn: Option<TransactionId>,
                ) -> Result<Grant, PersistenceError>;

            async fn update(
                &self,
                item: Grant,
                active_txn: Option<TransactionId>,
            ) -> Result<Grant, PersistenceError>;
        }
    }

    #[tokio::test]
    async fn test_can_introspect_token() {
        let rt_adapter = MockRTAdapter::new();
        let mut token_adapter = MockTokenAdapter::new();
        let mut grant_adapter = MockGrantAdapter::new();

        let grant = create_grant();
        let access_token = create_token(grant.id(), OffsetDateTime::now_utc());
        let at_clone = access_token.clone();
        token_adapter.expect_find().times(1).returning(move |id| {
            assert_eq!(id, &access_token.token);
            Ok(Some(at_clone.clone()))
        });
        grant_adapter.expect_find().times(1).returning(move |id| {
            assert_eq!(id, &grant.id());
            Ok(Some(grant.clone()))
        });

        let provider = init_provider(token_adapter, rt_adapter, grant_adapter).await;
        let app = oidc_router(None, provider.clone());
        let auth = Authorization::<Basic>::basic(CLIENT_ID, CLIENT_SECRET);
        let body = serde_urlencoded::to_string([("token", access_token.token)]).unwrap();
        let req = Request::builder()
            .uri("/introspect")
            .method(Method::POST)
            .header(AUTHORIZATION, auth.0.encode())
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed = serde_json::from_slice::<IntrospectionResponse>(&body).unwrap();
        assert!(parsed.is_active());
    }

    #[tokio::test]
    async fn test_can_introspect_expired_token() {
        let mut token_adapter = MockTokenAdapter::new();
        let mut rt_adapter = MockRTAdapter::new();
        let mut grant_adapter = MockGrantAdapter::new();

        let created = OffsetDateTime::now_utc() - Duration::minutes(15);
        let grant = create_grant();
        let access_token = create_token(grant.id(), created);
        let at_clone = access_token.clone();
        token_adapter.expect_find().times(1).returning(move |id| {
            assert_eq!(id, &access_token.token);
            Ok(Some(at_clone.clone()))
        });
        rt_adapter.expect_find().never();
        grant_adapter.expect_find().never();
        let provider = init_provider(token_adapter, rt_adapter, grant_adapter).await;
        let app = oidc_router(None, provider.clone());

        let auth = Authorization::<Basic>::basic(CLIENT_ID, CLIENT_SECRET);
        let body = serde_urlencoded::to_string([("token", access_token.token)]).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/introspect")
                    .method(Method::POST)
                    .header(AUTHORIZATION, auth.0.encode())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed = serde_json::from_slice::<IntrospectionResponse>(&body).unwrap();
        assert!(!parsed.is_active());
    }
    #[tokio::test]
    async fn test_introspect_inexistent_token() {
        let mut token_adapter = MockTokenAdapter::new();
        let mut rt_adapter = MockRTAdapter::new();
        let grant_adapter = MockGrantAdapter::new();

        token_adapter
            .expect_find()
            .times(1)
            .returning(move |_id| Ok(None));
        rt_adapter
            .expect_find()
            .times(1)
            .returning(move |_id| Ok(None));

        let provider = init_provider(token_adapter, rt_adapter, grant_adapter).await;
        let app = oidc_router(None, provider.clone());
        let auth = Authorization::<Basic>::basic(CLIENT_ID, CLIENT_SECRET);
        let body = serde_urlencoded::to_string([("token", "3886fb6b-978f-45d4-bc52-35efde2c1b78")])
            .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/introspect")
                    .method(Method::POST)
                    .header(AUTHORIZATION, auth.0.encode())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed = serde_json::from_slice::<IntrospectionResponse>(&body).unwrap();
        assert!(!parsed.is_active());
    }

    #[tokio::test]
    async fn test_introspect_refresh_token() {
        let mut token_adapter = MockTokenAdapter::new();
        let mut rt_adapter = MockRTAdapter::new();
        let mut grant_adapter = MockGrantAdapter::new();
        let created = OffsetDateTime::now_utc();
        let grant = create_grant();
        let refresh_token = create_refresh_token(created, grant.id());

        token_adapter
            .expect_find()
            .times(1)
            .returning(move |_id| Ok(None));

        let rt_clone = refresh_token.clone();
        rt_adapter.expect_find().times(1).returning(move |id| {
            assert_eq!(id, &refresh_token.token);
            Ok(Some(rt_clone.clone()))
        });
        grant_adapter.expect_find().times(1).returning(move |id| {
            assert_eq!(id, &grant.id());
            Ok(Some(grant.clone()))
        });

        let provider = init_provider(token_adapter, rt_adapter, grant_adapter).await;
        let app = oidc_router(None, provider.clone());
        let auth = Authorization::<Basic>::basic(CLIENT_ID, CLIENT_SECRET);
        let body = serde_urlencoded::to_string([("token", refresh_token.token)]).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/introspect")
                    .method(Method::POST)
                    .header(AUTHORIZATION, auth.0.encode())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed = serde_json::from_slice::<IntrospectionResponse>(&body).unwrap();
        assert!(parsed.is_active());
    }
    #[tokio::test]
    async fn test_introspect_refresh_token_with_hint() {
        let mut token_adapter = MockTokenAdapter::new();
        let mut rt_adapter = MockRTAdapter::new();
        let mut grant_adapter = MockGrantAdapter::new();
        let created = OffsetDateTime::now_utc();
        let grant = create_grant();
        let refresh_token = create_refresh_token(created, grant.id());

        token_adapter.expect_find().never();
        let rt_clone = refresh_token.clone();
        rt_adapter.expect_find().times(1).returning(move |id| {
            assert_eq!(id, &refresh_token.token);
            Ok(Some(rt_clone.clone()))
        });
        grant_adapter.expect_find().times(1).returning(move |id| {
            assert_eq!(id, &grant.id());
            Ok(Some(grant.clone()))
        });

        let provider = init_provider(token_adapter, rt_adapter, grant_adapter).await;
        let app = oidc_router(None, provider.clone());
        let auth = Authorization::<Basic>::basic(CLIENT_ID, CLIENT_SECRET);
        let body = serde_urlencoded::to_string([
            ("token", refresh_token.token.to_string()),
            ("token_type_hint", "refresh_token".to_string()),
        ])
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/introspect")
                    .method(Method::POST)
                    .header(AUTHORIZATION, auth.0.encode())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed = serde_json::from_slice::<IntrospectionResponse>(&body).unwrap();
        assert!(parsed.is_active());
    }
    async fn init_provider(
        token_adapter: MockTokenAdapter,
        rt_adapter: MockRTAdapter,
        grant_adapter: MockGrantAdapter,
    ) -> Arc<OpenIDProviderConfiguration> {
        tracing_subscriber::fmt::try_init().ok();

        let default_adapter_container = DefaultAdapterContainerBuilder::default()
            .token(Arc::new(token_adapter))
            .refresh(Arc::new(rt_adapter))
            .grant(Arc::new(grant_adapter))
            .build()
            .unwrap();

        let provider = Arc::new(
            OpenIDProviderConfigurationBuilder::default()
                .issuer("http://localhost:3000")
                .with_adapter(Box::new(default_adapter_container))
                .build()
                .expect("Error building openid provider"),
        );

        let _ = create_client(
            &provider,
            CLIENT_NAME,
            CLIENT_ID,
            CLIENT_SECRET,
            AUTH_METHOD,
        )
        .await;
        provider
    }

    fn create_token(grant_id: GrantID, created: OffsetDateTime) -> AccessToken {
        AccessToken::bearer(
            created,
            grant_id,
            Duration::minutes(10),
            Some(scopes!("openid")),
        )
    }

    fn create_refresh_token(created: OffsetDateTime, grant_id: GrantID) -> RefreshToken {
        let refresh_token = RefreshTokenBuilder::default()
            .token(Uuid::new_v4())
            .created(created)
            .grant_id(grant_id)
            .expires_in(Duration::minutes(10))
            .scopes(scopes!("openid"))
            .state(None)
            .nonce(None)
            .build()
            .unwrap();
        refresh_token
    }

    fn create_grant() -> Grant {
        let grant = GrantBuilder::new()
            .subject(Subject::new("test-sub"))
            .scopes(scopes!("openid"))
            .acr(Acr::new(vec!["0".to_string()]))
            .amr(None)
            .client_id(ClientID::from_str("1d8fca3b-a2f1-48c2-924d-843e5173a951").unwrap())
            .auth_time(OffsetDateTime::now_utc())
            .max_age(1000)
            .redirect_uri(None)
            .rejected_claims(HashSet::new())
            .claims(Claims::default())
            .build()
            .expect("Should always build successfully");
        grant
    }

    async fn create_client(
        config: &OpenIDProviderConfiguration,
        name: &str,
        id: &str,
        secret: &str,
        auth_method: AuthMethod,
    ) -> anyhow::Result<()> {
        let callback_url = "http://localhost:3000/callback".try_into()?;
        let client_metadata = ClientMetadataBuilder::default()
            .redirect_uris(vec![callback_url])
            .jwks(JwkSet::default())
            .token_endpoint_auth_method(auth_method)
            .id_token_signed_response_alg(EcdsaJwsAlgorithm::Es256)
            .client_name(name)
            .response_types(vec![
                ResponseTypeValue::Code,
                ResponseTypeValue::IdToken,
                ResponseTypeValue::Token,
            ])
            .grant_types(vec![GrantType::AuthorizationCode, GrantType::RefreshToken])
            .scope(scopes!("openid", "profile", "email", "phone", "address"))
            .build()?;

        let client = ClientInformation::new(
            ClientID::from_str(id)?,
            OffsetDateTime::now_utc(),
            Some(PlainTextSecret::from(secret.to_owned())),
            None,
            client_metadata,
        );
        register_client(config, client).await?;
        Ok(())
    }
}
