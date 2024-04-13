use crate::server::ServerError;
use anyhow::Context;
use axum::response::IntoResponse;
use hyper::StatusCode;
pub use oidc_core::configuration::{
    claims, clock, credentials as config_credentials, pkce, provider, request_object,
    routes as config_routes, ttl,
};
use std::net::SocketAddr;
use std::str::FromStr;

mod authenticated_request;
mod credentials;
pub(crate) mod extractors;
pub mod middleware;
mod routes;
pub mod server;
mod state;

pub(crate) fn socket_addr(adm_ip: &str, adm_port: &str) -> Result<SocketAddr, ServerError> {
    let adm_address = format!("{}:{}", adm_ip, adm_port);
    let addr =
        SocketAddr::from_str(&adm_address).context("Failed to parse admin server address")?;
    Ok(addr)
}

pub(crate) fn internal_error_response<D: Into<String>>(
    err_description: D,
) -> hyper::Response<axum::body::Body> {
    (StatusCode::INTERNAL_SERVER_ERROR, err_description.into()).into_response()
}
