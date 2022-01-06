use form_urlencoded::Serializer;
use url::Url;

use oidc_types::url_encodable::UrlEncodable;

use crate::context::OpenIDContext;
use crate::response_mode::encoder::Result;
use crate::response_mode::encoder::{AuthorisationResponse, ResponseModeEncoder};
use crate::response_mode::errors::EncodingError;

pub(crate) struct FragmentEncoder;

impl ResponseModeEncoder for FragmentEncoder {
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
        let fragment = Self::encode_fragment(parameters);
        callback_uri.set_fragment(Some(&fragment));
        Ok(AuthorisationResponse::Redirect(callback_uri))
    }
}

impl FragmentEncoder {
    fn encode_fragment<T: UrlEncodable>(parameters: T) -> String {
        let mut serializer = Serializer::new("".to_string());
        serializer.extend_pairs(parameters.params()).finish()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use url::Url;

    use crate::response_mode::encoder::fragment::FragmentEncoder;

    #[test]
    fn test_can_append_fragment_to_url() {
        let mut params = HashMap::new();
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
