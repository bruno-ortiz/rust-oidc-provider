use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use tracing::error;
use url::Url;

use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_types::discovery::OIDCProviderMetadataBuilder;
use oidc_types::issuer::Issuer;
use oidc_types::scopes::Scope;

pub const DISCOVERY_ROUTE: &str = "/.well-known/openid-configuration";

pub async fn discovery<'a>(
    State(provider): State<Arc<OpenIDProviderConfiguration>>,
) -> axum::response::Result<Response> {
    let issuer = provider.issuer();
    let routes = provider.routes();
    let scopes_supported: Vec<Scope> = provider
        .scopes_supported()
        .inner()
        .clone()
        .into_iter()
        .chain(
            provider
                .claims_supported()
                .iter()
                .flat_map(|it| it.unwrap_scoped())
                .map(|it| Scope::simple(it.0)),
        )
        .collect();
    let metadata = OIDCProviderMetadataBuilder::default()
        .issuer(issuer)
        .authorization_endpoint(url(issuer, routes.authorisation))
        .token_endpoint(url(issuer, routes.token))
        .token_endpoint_auth_methods_supported(provider.token_endpoint_auth_methods_supported())
        .token_endpoint_auth_signing_alg_values_supported(
            provider.token_endpoint_auth_signing_alg_values_supported(),
        )
        .userinfo_endpoint(url(issuer, routes.userinfo))
        .userinfo_signing_alg_values_supported(provider.userinfo_signing_alg_values_supported())
        .jwks_uri(url(issuer, routes.jwks))
        .response_types_supported(provider.response_types_supported())
        .response_modes_supported(provider.response_modes_supported())
        .grant_types_supported(provider.grant_types_supported())
        .scopes_supported(scopes_supported)
        .claims_supported(
            provider
                .claims_supported()
                .iter()
                .flat_map(|it| it.claims())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>(),
        )
        .claim_types_supported(provider.claim_types_supported().as_ref())
        .claims_parameter_supported(provider.claims_parameter_supported())
        .tls_client_certificate_bound_access_tokens(false) //todo: implement mtls
        .request_parameter_supported(provider.request_object().request)
        .request_uri_parameter_supported(provider.request_object().request_uri)
        .require_request_uri_registration(provider.request_object().require_uri_registration)
        .request_object_signing_alg_values_supported(
            provider.request_object_signing_alg_values_supported(),
        )
        .request_object_encryption_alg_values_supported(
            provider
                .request_object_encryption_alg_values_supported()
                .as_ref(),
        )
        .request_object_encryption_enc_values_supported(
            provider
                .request_object_encryption_enc_values_supported()
                .as_ref(),
        )
        .id_token_signing_alg_values_supported(provider.id_token_signing_alg_values_supported())
        .id_token_encryption_alg_values_supported(
            provider.id_token_encryption_alg_values_supported().as_ref(),
        )
        .id_token_encryption_enc_values_supported(
            provider.id_token_encryption_enc_values_supported().as_ref(),
        )
        .authorization_signing_alg_values_supported(
            provider
                .authorization_signing_alg_values_supported()
                .as_ref(),
        )
        .authorization_encryption_alg_values_supported(
            provider
                .authorization_encryption_alg_values_supported()
                .as_ref(),
        )
        .authorization_encryption_enc_values_supported(
            provider
                .authorization_encryption_enc_values_supported()
                .as_ref(),
        )
        .subject_types_supported(provider.subject_types_supported())
        .code_challenge_methods_supported(provider.pkce().methods_supported())
        .build()
        .map_err(|err| {
            error!("Error builder oidc metadata {}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        })?;
    Ok(Json(metadata).into_response())
}

fn url(issuer: &Issuer, path: &str) -> Url {
    issuer.inner().join(path).expect("Should be a valid url")
}
