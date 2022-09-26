use indexmap::IndexMap;
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;
use josekit::Value;
use time::{Duration, OffsetDateTime};

use oidc_types::jose::jwt2::{SignedJWT, JWT};
use oidc_types::jose::JwsHeaderExt;
use oidc_types::response_mode::ResponseMode;

use crate::configuration::OpenIDProviderConfiguration;
use crate::keystore::KeyUse;
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
        parameters: IndexMap<String, String>,
    ) -> Result<AuthorisationResponse> {
        let configuration = OpenIDProviderConfiguration::instance();
        let alg = &context.client.metadata().authorization_signed_response_alg;
        let keystore = context.client.server_keystore(alg);
        let signing_key = keystore
            .select(KeyUse::Sig)
            .alg(alg.name())
            .first()
            .ok_or(EncodingError::MissingSigningKey)?;
        let header = JwsHeader::from_key(signing_key);
        let payload = self.build_payload(configuration, context, parameters);
        let jwt = SignedJWT::new(header, payload, signing_key)
            .map_err(EncodingError::JwtCreationError)?;

        let mut params = IndexMap::new();
        params.insert("response".to_owned(), jwt.serialized_owned());

        match context.response_mode {
            ResponseMode::QueryJwt => QueryEncoder.encode(context, params),
            ResponseMode::FragmentJwt => FragmentEncoder.encode(context, params),
            ResponseMode::FormPostJwt => todo!("implement"),
            _ => unreachable!("Should never reach here"),
        }
    }
}

impl EncoderDecider for JwtEncoder {
    fn can_encode(&self, response_mode: ResponseMode) -> bool {
        response_mode == ResponseMode::Jwt
            || response_mode == ResponseMode::QueryJwt
            || response_mode == ResponseMode::FragmentJwt
            || response_mode == ResponseMode::FormPostJwt
    }
}

impl JwtEncoder {
    fn build_payload(
        &self,
        configuration: &OpenIDProviderConfiguration,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> JwtPayload {
        let mut payload = JwtPayload::new();
        payload.set_issuer(configuration.issuer());
        payload.set_audience(vec![context.client.id().to_string()]);
        let exp = OffsetDateTime::now_utc() + Duration::minutes(EXP_IN_MINUTES);
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
