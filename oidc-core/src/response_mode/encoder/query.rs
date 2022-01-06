use url::Url;

use oidc_types::url_encodable::UrlEncodable;

use crate::context::OpenIDContext;
use crate::response_mode::encoder::Result;
use crate::response_mode::encoder::{AuthorisationResponse, ResponseModeEncoder};
use crate::response_mode::errors::EncodingError;

pub(crate) struct QueryEncoder;

impl ResponseModeEncoder for QueryEncoder {
    fn encode<T: UrlEncodable>(
        &self,
        context: &OpenIDContext,
        parameters: T,
    ) -> Result<AuthorisationResponse> {
        let client = &context.client;
        let callback_uri_template = client
            .metadata
            .redirect_uris
            .first()
            .ok_or(EncodingError::MissingRedirectUri(client.id.clone()))?;
        let mut callback_uri = callback_uri_template.clone();
        callback_uri
            .query_pairs_mut()
            .extend_pairs(parameters.params())
            .finish();
        Ok(AuthorisationResponse::Redirect(callback_uri))
    }
}
