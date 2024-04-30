use indexmap::IndexMap;
use josekit::jwk::Jwk;
use url::Url;

use oidc_types::response_mode::ResponseMode;

use crate::configuration::OpenIDProviderConfiguration;
use crate::models::client::ClientInformation;
use crate::response_mode::encoder::fragment::FragmentEncoder;
use crate::response_mode::encoder::jwt::JwtEncoder;
use crate::response_mode::encoder::query::QueryEncoder;
use crate::response_mode::error::Result;

use super::{AuthorisationResult, Error};

pub(crate) mod fragment;
pub(crate) mod jwt;
pub(crate) mod query;

pub struct EncodingContext<'a> {
    pub client: &'a ClientInformation,
    pub redirect_uri: &'a Url,
    pub response_mode: ResponseMode,
    pub provider: &'a OpenIDProviderConfiguration,
    pub signing_key: Option<Jwk>,
    pub encryption_key: Option<Jwk>,
}

pub trait ResponseModeEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> Result<AuthorisationResult>;
}

#[derive(Default, Copy, Clone)]
pub struct DynamicResponseModeEncoder;

impl ResponseModeEncoder for DynamicResponseModeEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> Result<AuthorisationResult> {
        let response_mode = context.response_mode;

        if !context
            .provider
            .response_modes_supported()
            .contains(&response_mode)
        {
            return Err(Error::InvalidResponseMode(response_mode));
        }

        match response_mode {
            ResponseMode::Query => QueryEncoder.encode(context, parameters),
            ResponseMode::Fragment => FragmentEncoder.encode(context, parameters),
            ResponseMode::FormPost => todo!("implement form post encoder"),
            _ => JwtEncoder.encode(context, parameters),
        }
    }
}
