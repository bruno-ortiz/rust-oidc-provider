use indexmap::IndexMap;
use oidc_types::response_mode::ResponseMode;

use crate::response_mode::encoder::{AuthorisationResponse, EncoderDecider, ResponseModeEncoder};
use crate::response_mode::encoder::{EncodingContext, Result};

pub(crate) struct QueryEncoder;

impl ResponseModeEncoder for QueryEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> Result<AuthorisationResponse> {
        let mut callback_uri = context.redirect_uri.clone();
        callback_uri
            .query_pairs_mut()
            .extend_pairs(parameters)
            .finish();
        Ok(AuthorisationResponse::Redirect(callback_uri))
    }
}

impl EncoderDecider for QueryEncoder {
    fn can_encode(&self, response_mode: &ResponseMode) -> bool {
        *response_mode == ResponseMode::Query
    }
}
