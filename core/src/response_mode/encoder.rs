use indexmap::IndexMap;
use std::collections::HashMap;

use url::Url;

use format as f;
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

pub(crate) mod fragment;
pub(crate) mod jwt;
pub(crate) mod query;

pub(crate) type Result<T> = std::result::Result<T, EncodingError>;

pub struct EncodingContext<'a> {
    pub client: &'a ClientInformation,
    pub redirect_uri: &'a Url,
    pub response_mode: ResponseMode,
}

pub trait ResponseModeEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> Result<AuthorisationResponse>;
}

pub trait EncoderDecider: ResponseModeEncoder {
    fn can_encode(&self, response_mode: ResponseMode) -> bool;
}

pub enum AuthorisationResponse {
    Redirect(Url),
    FormPost(Url, HashMap<String, String>),
}

pub struct DynamicResponseModeEncoder {
    encoders: Vec<Box<dyn EncoderDecider + Send + Sync>>,
}

impl ResponseModeEncoder for DynamicResponseModeEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> Result<AuthorisationResponse> {
        let response_mode = context.response_mode;
        let encoder = self
            .encoders
            .iter()
            .find(|&decider| decider.can_encode(response_mode))
            .ok_or_else(|| {
                EncodingError::InternalError(f!(
                    "Encoder not found for response_mode {response_mode:?}"
                ))
            })?;
        encoder.encode(context, parameters)
    }
}

impl From<&OpenIDProviderConfiguration> for DynamicResponseModeEncoder {
    fn from(cfg: &OpenIDProviderConfiguration) -> Self {
        let mut encoder = DynamicResponseModeEncoder::new();
        encoder.push(Box::new(QueryEncoder));
        encoder.push(Box::new(FragmentEncoder));

        if cfg.jwt_secure_response_mode() {
            encoder.push(Box::new(JwtEncoder))
        }
        encoder
    }
}

impl DynamicResponseModeEncoder {
    fn new() -> Self {
        DynamicResponseModeEncoder { encoders: vec![] }
    }

    pub fn push(&mut self, encoder: Box<dyn EncoderDecider + Send + Sync>) {
        self.encoders.push(encoder);
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
