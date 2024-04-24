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

pub enum AuthorisationResponse {
    Redirect(Url),
    FormPost(Url, HashMap<String, String>),
}

impl AuthorisationResponse {
    pub fn create_response<P: UrlEncodable>(
        context: EncodingContext,
        parameters: P,
    ) -> Result<AuthorisationResponse> {
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

fn encode_err(context: &EncodingContext, err: OpenIdError) -> Result<AuthorisationResponse> {
    match context.response_mode {
        ResponseMode::Fragment => FragmentEncoder.encode(context, err.params()),
        ResponseMode::Query => QueryEncoder.encode(context, err.params()),
        _ => Err(Error::InternalError(err.into())),
    }
}
