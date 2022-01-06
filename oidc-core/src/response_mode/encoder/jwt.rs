use form_urlencoded::Serializer;
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;
use url::Url;

use oidc_types::jose::jwt::JWT;
use oidc_types::url_encodable::UrlEncodable;

use crate::context::OpenIDContext;
use crate::response_mode::encoder::Result;
use crate::response_mode::encoder::{AuthorisationResponse, ResponseModeEncoder};
use crate::response_mode::errors::EncodingError;

pub(crate) struct JwtEncoder;

impl ResponseModeEncoder for JwtEncoder {
    fn encode<T: UrlEncodable>(
        &self,
        context: &OpenIDContext,
        parameters: T,
    ) -> Result<AuthorisationResponse> {
        let client = &context.client;
        let signing_key = context
            .configuration
            .signing_key()
            .ok_or(EncodingError::MissingSigningKey)?;
        let header = JwsHeader::new();
        let payload = JwtPayload::new();
        let jwt = JWT::new(header, payload, signing_key)
            .map_err(|err| EncodingError::JwtCreationError(err))?;

        jwt.serialize();
        todo!("")
    }
}

#[cfg(test)]
mod tests {}
