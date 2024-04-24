use indexmap::IndexMap;

use crate::response_mode::encoder::{Authorisation, ResponseModeEncoder};
use crate::response_mode::encoder::{EncodingContext, Result};

pub(crate) struct QueryEncoder;

impl ResponseModeEncoder for QueryEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> Result<Authorisation> {
        let mut callback_uri = context.redirect_uri.clone();
        callback_uri
            .query_pairs_mut()
            .extend_pairs(parameters)
            .finish();
        Ok(Authorisation::Redirect(callback_uri))
    }
}
