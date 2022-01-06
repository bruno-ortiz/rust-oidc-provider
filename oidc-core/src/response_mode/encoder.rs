use std::collections::HashMap;

use url::Url;

use crate::context::OpenIDContext;
use crate::response_mode::errors::EncodingError;
use crate::response_type::UrlEncodable;

pub(crate) mod fragment;
mod jwt;
pub(crate) mod query;

pub(crate) type Result<T> = std::result::Result<T, EncodingError>;

pub trait ResponseModeEncoder {
    fn encode<T: UrlEncodable>(
        &self,
        context: &OpenIDContext,
        parameters: T,
    ) -> Result<AuthorisationResponse>;
}

pub enum AuthorisationResponse {
    Redirect(Url),
    FormPost(Url, HashMap<String, String>),
}
