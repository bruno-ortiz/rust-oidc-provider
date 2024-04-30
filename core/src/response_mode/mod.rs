pub mod encoder;
mod error;

use self::encoder::{
    fragment::FragmentEncoder, query::QueryEncoder, DynamicResponseModeEncoder, EncodingContext,
    ResponseModeEncoder,
};
pub use self::error::{Error, Result};
use crate::error::OpenIdError;
use oidc_types::{response_mode::ResponseMode, url_encodable::UrlEncodable};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, PartialEq, Eq)]
pub enum AuthorisationResult {
    Redirect(Url),
    FormPost(Url, HashMap<String, String>),
}

impl AuthorisationResult {
    pub fn new<P: UrlEncodable>(
        context: EncodingContext,
        parameters: P,
    ) -> Result<AuthorisationResult> {
        let parameters = parameters.params();
        let result = DynamicResponseModeEncoder
            .encode(&context, parameters)
            .map_err(OpenIdError::server_error);
        match result {
            Ok(res) => Ok(res),
            Err(err) => encode_err(&context, err),
        }
    }
}

fn encode_err(context: &EncodingContext, err: OpenIdError) -> Result<AuthorisationResult> {
    match context.response_mode {
        ResponseMode::Fragment => FragmentEncoder.encode(context, err.params()),
        ResponseMode::Query => QueryEncoder.encode(context, err.params()),
        _ => Err(Error::InternalError(err.into())),
    }
}
