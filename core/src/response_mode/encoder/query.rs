use indexmap::IndexMap;

use crate::response_mode::encoder::{AuthorisationResult, ResponseModeEncoder};
use crate::response_mode::encoder::{EncodingContext, Result};

pub(crate) struct QueryEncoder;

impl ResponseModeEncoder for QueryEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> Result<AuthorisationResult> {
        let mut callback_uri = context.redirect_uri.clone();
        callback_uri
            .query_pairs_mut()
            .extend_pairs(parameters)
            .finish();
        Ok(AuthorisationResult::Redirect(callback_uri))
    }
}
