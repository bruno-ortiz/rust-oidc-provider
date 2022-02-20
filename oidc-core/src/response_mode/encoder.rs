use std::collections::HashMap;
use std::sync::Arc;

use url::Url;

use format as f;
use oidc_types::client::ClientInformation;
use oidc_types::response_mode::ResponseMode;
use oidc_types::url_encodable::UrlEncodable;

use crate::configuration::OpenIDProviderConfiguration;
use crate::response_mode::encoder::fragment::FragmentEncoder;
use crate::response_mode::encoder::jwt::JwtEncoder;
use crate::response_mode::encoder::query::QueryEncoder;
use crate::response_mode::errors::EncodingError;
use crate::response_type::errors::OpenIdError;
use crate::services::authorisation::AuthorisationError;

pub(crate) mod fragment;
pub(crate) mod jwt;
pub(crate) mod query;

pub(crate) type Result<T> = std::result::Result<T, EncodingError>;

pub struct EncodingContext<'a> {
    pub client: &'a ClientInformation,
    pub configuration: &'a OpenIDProviderConfiguration,
    pub redirect_uri: &'a Url,
    pub response_mode: ResponseMode,
}

pub trait ResponseModeEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: HashMap<String, String>,
    ) -> Result<AuthorisationResponse>;
}

pub trait EncoderDecider: ResponseModeEncoder {
    fn can_encode(&self, response_mode: &ResponseMode) -> bool;
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
        parameters: HashMap<String, String>,
    ) -> Result<AuthorisationResponse> {
        let response_mode = &context.response_mode;
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

        if cfg.is_jarm_enabled() {
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

impl<T> ResponseModeEncoder for Arc<T>
where
    T: ResponseModeEncoder,
{
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: HashMap<String, String>,
    ) -> Result<AuthorisationResponse> {
        T::encode(self, context, parameters)
    }
}

pub fn encode_response<E: ResponseModeEncoder, P: UrlEncodable>(
    context: EncodingContext,
    encoder: &E,
    parameters: P,
) -> std::result::Result<AuthorisationResponse, AuthorisationError> {
    let result = encoder
        .encode(&context, parameters.params())
        .map_err(|err| OpenIdError::ServerError { source: err.into() });
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
