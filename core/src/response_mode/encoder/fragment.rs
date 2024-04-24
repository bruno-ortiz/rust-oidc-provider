use form_urlencoded::Serializer;
use indexmap::IndexMap;

use crate::response_mode::encoder::{Authorisation, ResponseModeEncoder};
use crate::response_mode::encoder::{EncodingContext, Result};

pub(crate) struct FragmentEncoder;

impl ResponseModeEncoder for FragmentEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> Result<Authorisation> {
        let mut callback_uri = context.redirect_uri.clone();
        let fragment = Self::encode_fragment(parameters);
        callback_uri.set_fragment(Some(&fragment));
        Ok(Authorisation::Redirect(callback_uri))
    }
}

impl FragmentEncoder {
    fn encode_fragment(parameters: IndexMap<String, String>) -> String {
        let mut serializer = Serializer::new("".to_string());
        serializer.extend_pairs(parameters).finish()
    }
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;
    use url::Url;

    use crate::response_mode::encoder::fragment::FragmentEncoder;

    #[test]
    fn test_can_append_fragment_to_url() {
        let mut params = IndexMap::new();
        params.insert("code".to_string(), "some_code".to_string());
        params.insert("token".to_string(), "some_token".to_string());

        let mut url = Url::parse("https://www.test.com").unwrap();
        let fragment = FragmentEncoder::encode_fragment(params);
        url.set_fragment(Some(&fragment));
        assert_eq!(
            "https://www.test.com/#code=some_code&token=some_token",
            url.as_str()
        )
    }
}
