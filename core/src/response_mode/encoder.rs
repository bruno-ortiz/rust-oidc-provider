use std::collections::HashMap;

use indexmap::IndexMap;
use url::Url;

use oidc_types::response_mode::ResponseMode;
use oidc_types::state::State;
use oidc_types::url_encodable::UrlEncodable;

use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::models::client::ClientInformation;
use crate::response_mode::encoder::fragment::FragmentEncoder;
use crate::response_mode::encoder::jwt::JwtEncoder;
use crate::response_mode::encoder::query::QueryEncoder;
use crate::response_mode::errors::EncodingError;
use crate::services::authorisation::AuthorisationError;
use crate::services::keystore::KeystoreService;

pub(crate) mod fragment;
pub(crate) mod jwt;
pub(crate) mod query;

pub(crate) type Result<T> = std::result::Result<T, EncodingError>;

pub struct EncodingContext<'a> {
    pub client: &'a ClientInformation,
    pub redirect_uri: &'a Url,
    pub response_mode: ResponseMode,
    pub provider: &'a OpenIDProviderConfiguration,
    pub keystore_service: &'a KeystoreService,
}

pub trait ResponseModeEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> Result<AuthorisationResponse>;
}

pub enum AuthorisationResponse {
    Redirect(Url),
    FormPost(Url, HashMap<String, String>),
}

#[derive(Default, Copy, Clone)]
pub struct DynamicResponseModeEncoder;

impl ResponseModeEncoder for DynamicResponseModeEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> Result<AuthorisationResponse> {
        let response_mode = context.response_mode;

        if !context
            .provider
            .response_modes_supported()
            .contains(&response_mode)
        {
            todo!("Return error, unsupported responde mode")
        }

        match response_mode {
            ResponseMode::Query => QueryEncoder.encode(context, parameters),
            ResponseMode::Fragment => FragmentEncoder.encode(context, parameters),
            ResponseMode::FormPost => todo!("implement form post encoder"),
            _ => JwtEncoder.encode(context, parameters),
        }
    }
}

pub fn encode_response<E: ResponseModeEncoder, P: UrlEncodable>(
    context: EncodingContext,
    encoder: &E,
    parameters: P,
    state: Option<State>,
) -> std::result::Result<AuthorisationResponse, AuthorisationError> {
    let mut parameters = parameters.params();
    if let Some(state) = state {
        parameters = (parameters, state).params();
    }
    let result = encoder
        .encode(&context, parameters)
        .map_err(OpenIdError::server_error);
    match result {
        Ok(res) => Ok(res),
        Err(err) => encode_err(&context, err),
    }
}

fn encode_err(
    context: &EncodingContext,
    err: OpenIdError,
) -> std::result::Result<AuthorisationResponse, AuthorisationError> {
    match context.response_mode {
        ResponseMode::Fragment => FragmentEncoder
            .encode(context, err.params())
            .map_err(|err| AuthorisationError::InternalError(err.into())),
        ResponseMode::Query => QueryEncoder
            .encode(context, err.params())
            .map_err(|err| AuthorisationError::InternalError(err.into())),
        _ => Err(AuthorisationError::InternalError(err.into())),
    }
}
