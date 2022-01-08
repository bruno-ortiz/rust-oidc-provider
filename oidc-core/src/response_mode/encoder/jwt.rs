use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use form_urlencoded::Serializer;
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;
use josekit::Value;
use url::Url;

use oidc_types::jose::jwt::JWT;
use oidc_types::jose::JwsHeaderExt;
use oidc_types::response_mode::ResponseMode;
use oidc_types::url_encodable::UrlEncodable;

use crate::context::OpenIDContext;
use crate::response_mode::encoder::fragment::FragmentEncoder;
use crate::response_mode::encoder::query::QueryEncoder;
use crate::response_mode::encoder::Result;
use crate::response_mode::encoder::{AuthorisationResponse, ResponseModeEncoder};
use crate::response_mode::errors::EncodingError;

const EXP_IN_MINUTES: i64 = 5i64;

pub(crate) struct JwtEncoder;

impl ResponseModeEncoder for JwtEncoder {
    fn encode<T: UrlEncodable>(
        &self,
        context: &OpenIDContext,
        parameters: T,
    ) -> Result<AuthorisationResponse> {
        let signing_key = context
            .configuration
            .signing_key()
            .ok_or(EncodingError::MissingSigningKey)?;
        let mut header = JwsHeader::from_key(signing_key);
        let payload = Self::build_payload(context, parameters);
        //todo: add state to the response
        let jwt = JWT::encode_string(header, payload, signing_key)
            .map_err(|err| EncodingError::JwtCreationError(err))?;

        let mut params = HashMap::new();
        params.insert("response".to_owned(), jwt);

        match context.response_mode() {
            ResponseMode::QueryJwt => QueryEncoder.encode(context, params),
            ResponseMode::FragmentJwt => FragmentEncoder.encode(context, params),
            ResponseMode::FormPostJwt => todo!("implement"),
            _ => unreachable!("Should never reach here"),
        }
    }
}

impl JwtEncoder {
    fn build_payload<T: UrlEncodable>(context: &OpenIDContext, parameters: T) -> JwtPayload {
        let mut payload = JwtPayload::new();
        payload.set_issuer(context.configuration.issuer());
        payload.set_audience(vec![context.client.id.to_string()]);
        let exp = Utc::now() + Duration::minutes(EXP_IN_MINUTES);
        payload.set_expires_at(&exp.into());
        for (key, value) in parameters.params() {
            payload.set_claim(&key, Some(Value::String(value)));
        }
        payload
    }
}

#[cfg(test)]
mod tests {}
