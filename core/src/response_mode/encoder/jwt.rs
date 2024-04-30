use indexmap::IndexMap;
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;
use josekit::Value;
use time::Duration;

use oidc_types::jose::jws::JwsHeaderExt;
use oidc_types::jose::jwt2::{SignedJWT, JWT};
use oidc_types::response_mode::ResponseMode;

use crate::configuration::clock::Clock;
use crate::configuration::OpenIDProviderConfiguration;
use crate::response_mode::encoder::fragment::FragmentEncoder;
use crate::response_mode::encoder::query::QueryEncoder;
use crate::response_mode::encoder::EncodingContext;
use crate::response_mode::encoder::{AuthorisationResult, ResponseModeEncoder};
use crate::response_mode::error::{Error, Result};

const EXP_IN_MINUTES: i64 = 5i64;

pub(crate) struct JwtEncoder;

impl ResponseModeEncoder for JwtEncoder {
    fn encode(
        &self,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> Result<AuthorisationResult> {
        let mut params = IndexMap::new();
        let signing_key = context
            .signing_key
            .as_ref()
            .ok_or(Error::MissingSigningKey)?;
        let header = JwsHeader::from_key(signing_key);
        let payload = self.build_payload(context.provider, context, parameters);
        let jwt = SignedJWT::new(header, payload, signing_key).map_err(Error::JwtCreationError)?;
        if let Some(enc_data) = context.client.metadata().authorization_encryption_data() {
            let encrption_key = context
                .encryption_key
                .as_ref()
                .ok_or(Error::MissingEncryptionKey)?;
            let enc_jwt = jwt.encrypt(encrption_key, enc_data.enc)?;
            params.insert("response".to_owned(), enc_jwt.serialized_owned());
        } else {
            params.insert("response".to_owned(), jwt.serialized_owned());
        }

        match context.response_mode {
            ResponseMode::QueryJwt => QueryEncoder.encode(context, params),
            ResponseMode::FragmentJwt => FragmentEncoder.encode(context, params),
            ResponseMode::FormPostJwt => todo!("implement"),
            _ => unreachable!("Should never reach here"),
        }
    }
}

impl JwtEncoder {
    fn build_payload(
        &self,
        provider: &OpenIDProviderConfiguration,
        context: &EncodingContext,
        parameters: IndexMap<String, String>,
    ) -> JwtPayload {
        let clock = provider.clock_provider();
        let mut payload = JwtPayload::new();
        payload.set_issuer(provider.issuer());
        payload.set_audience(vec![context.client.id().to_string()]);
        let exp = clock.now() + Duration::minutes(EXP_IN_MINUTES); //TODO: review this exp
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
