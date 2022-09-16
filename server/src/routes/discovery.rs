use axum::http::StatusCode;
use axum::Json;
use tracing::error;
use url::Url;

use oidc_core::configuration::OpenIDProviderConfiguration;
use oidc_types::discovery::{OIDCProviderMetadata, OIDCProviderMetadataBuilder};
use oidc_types::issuer::Issuer;

pub const DISCOVERY_ROUTE: &str = "/.well-known/openid-configuration";

pub async fn discovery() -> axum::response::Result<Json<OIDCProviderMetadata>> {
    let configuration = OpenIDProviderConfiguration::instance();
    let issuer = configuration.issuer();
    let routes = configuration.routes();
    let metadata = OIDCProviderMetadataBuilder::default()
        .issuer(issuer.clone())
        .authorization_endpoint(url(issuer, routes.authorisation))
        .jwks_uri(url(issuer, routes.jwks))
        .response_types_supported(configuration.response_types_supported().clone())
        .response_modes_supported(configuration.response_modes_supported().clone())
        .grant_types_supported(configuration.grant_types_supported().clone())
        .scopes_supported(
            configuration
                .scopes_supported()
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        )
        .claims_supported(configuration.claims_supported().clone())
        .claim_types_supported(configuration.claim_types_supported().clone())
        .claims_parameter_supported(configuration.claims_parameter_supported())
        .tls_client_certificate_bound_access_tokens(false) //todo: implement mtls
        .request_parameter_supported(configuration.request_parameter_supported())
        .request_uri_parameter_supported(configuration.request_uri_parameter_supported())
        .require_request_uri_registration(configuration.require_request_uri_registration())
        .request_object_signing_alg_values_supported(
            configuration
                .request_object_signing_alg_values_supported()
                .clone(),
        )
        .request_object_encryption_alg_values_supported(
            configuration
                .request_object_encryption_alg_values_supported()
                .clone(),
        )
        .request_object_encryption_enc_values_supported(
            configuration
                .request_object_encryption_enc_values_supported()
                .clone(),
        )
        .id_token_signing_alg_values_supported(
            configuration
                .id_token_signing_alg_values_supported()
                .clone(),
        )
        .id_token_encryption_alg_values_supported(
            configuration
                .id_token_encryption_alg_values_supported()
                .clone(),
        )
        .id_token_encryption_enc_values_supported(
            configuration
                .id_token_encryption_enc_values_supported()
                .clone(),
        )
        .authorization_signing_alg_values_supported(
            configuration
                .authorization_signing_alg_values_supported()
                .clone(),
        )
        .authorization_encryption_alg_values_supported(
            configuration
                .authorization_encryption_alg_values_supported()
                .clone(),
        )
        .authorization_encryption_enc_values_supported(
            configuration
                .authorization_encryption_enc_values_supported()
                .clone(),
        )
        .subject_types_supported(configuration.subject_types_supported().clone())
        .code_challenge_methods_supported(configuration.pkce().methods_supported().clone())
        .build()
        .map_err(|err| {
            error!("Error builder oidc metadata {}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        })?;
    Ok(Json(metadata))
}

fn url(issuer: &Issuer, path: &str) -> Url {
    issuer.inner().join(path).expect("Should be a valid url")
}

mod tests {}
