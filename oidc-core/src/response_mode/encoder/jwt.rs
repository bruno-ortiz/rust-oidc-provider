use std::collections::HashMap;

use chrono::{Duration, Utc};
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;
use josekit::Value;

use oidc_types::jose::jwt::JWT;
use oidc_types::jose::JwsHeaderExt;
use oidc_types::response_mode::ResponseMode;

use crate::response_mode::encoder::fragment::FragmentEncoder;
use crate::response_mode::encoder::query::QueryEncoder;
use crate::response_mode::encoder::{AuthorisationResponse, EncoderDecider, ResponseModeEncoder};
use crate::response_mode::encoder::{EncodingContext, Result};
use crate::response_mode::errors::EncodingError;

const EXP_IN_MINUTES: i64 = 5i64;

pub(crate) struct JwtEncoder;

impl ResponseModeEncoder for JwtEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: HashMap<String, String>,
    ) -> Result<AuthorisationResponse> {
        let signing_key = context
            .configuration
            .signing_key()
            .ok_or(EncodingError::MissingSigningKey)?;
        let header = JwsHeader::from_key(signing_key);
        let payload = self.build_payload(context, parameters);
        //todo: add state to the response
        let jwt = JWT::encode_string(header, payload, signing_key)
            .map_err(EncodingError::JwtCreationError)?;

        let mut params = HashMap::new();
        params.insert("response".to_owned(), jwt);

        match context.response_mode {
            ResponseMode::QueryJwt => QueryEncoder.encode(context, params),
            ResponseMode::FragmentJwt => FragmentEncoder.encode(context, params),
            ResponseMode::FormPostJwt => todo!("implement"),
            _ => unreachable!("Should never reach here"),
        }
    }
}

impl EncoderDecider for JwtEncoder {
    fn can_encode(&self, response_mode: &ResponseMode) -> bool {
        *response_mode == ResponseMode::Jwt
            || *response_mode == ResponseMode::QueryJwt
            || *response_mode == ResponseMode::FragmentJwt
            || *response_mode == ResponseMode::FormPostJwt
    }
}

impl JwtEncoder {
    fn build_payload(
        &self,
        context: &EncodingContext,
        parameters: HashMap<String, String>,
    ) -> JwtPayload {
        let mut payload = JwtPayload::new();
        payload.set_issuer(context.configuration.issuer());
        payload.set_audience(vec![context.client.id.to_string()]);
        let exp = Utc::now() + Duration::minutes(EXP_IN_MINUTES);
        payload.set_expires_at(&exp.into());
        for (key, value) in parameters {
            payload
                .set_claim(&key, Some(Value::String(value)))
                .unwrap_or_else(|_| panic!("Cannot set {key} on JWT"));
        }
        payload
    }
}

#[cfg(test)]
mod tests {}
