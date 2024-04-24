use std::sync::Arc;

use anyhow::Context;
use derive_new::new;
use josekit::jwt::alg::unsecured::UnsecuredJwsAlgorithm;
use oidc_types::jose::jws::SigningAlgorithm;
use url::Url;

use oidc_types::jose::jwt2::JWT;
use oidc_types::jose::Algorithm;

use crate::authorisation_request::AuthorisationRequest;
use crate::configuration::request_object::RequestObjectConfiguration;
use crate::configuration::OpenIDProviderConfiguration;
use crate::id_token_builder::JwtPayloadExt;
use crate::jwt::{GenericJWT, ValidJWT};
use crate::models::client::ClientInformation;
use crate::services::keystore::KeystoreService;

mod error {
    use oidc_types::jose::error::JWTError;
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("Invalid request, authorization request should not provide both request and request_uri parameter")]
        RequestObjAndUri,
        #[error("Missing alg in request_object Header")]
        MissingAlg,
        #[error("request object alg header {0} differs from the algorithm registered for the client: {1}")]
        AlgMismatch(String, String),
        #[error("Request object must be signed")]
        UnsignedRequestObject,
        #[error("Invalid request_object: {0}")]
        InvalidRequestObject(#[source] JWTError),
        #[error(transparent)]
        Internal(#[from] anyhow::Error),
    }

    pub type Result<T> = std::result::Result<T, Error>;
}

pub use error::{Error, Result};

#[derive(Clone, new)]
pub struct RequestObjectProcessor {
    provider: Arc<OpenIDProviderConfiguration>,
    keystore_service: Arc<KeystoreService>,
}

impl RequestObjectProcessor {
    pub async fn process(
        &self,
        request: &AuthorisationRequest,
        client: &ClientInformation,
    ) -> Result<Option<AuthorisationRequest>> {
        let ro_config = self.provider.request_object();
        if let Some(request_obj) = self.get_request_object(request, client, ro_config).await? {
            let alg = request_obj.alg().ok_or(Error::MissingAlg)?;

            validate_request_obj_metadata(client, &alg, ro_config)?;

            let keystore = self
                .keystore_service
                .keystore(client, &alg)
                .await
                .context("Error getting keystore")?;
            let validated =
                ValidJWT::validate(request_obj, &keystore).map_err(Error::InvalidRequestObject)?;
            let authorisation_request = validated
                .payload()
                .convert::<AuthorisationRequest>()
                .context("Failed to parse request_obj as AuthorisationRequest")?;
            Ok(Some(authorisation_request))
        } else {
            Ok(None)
        }
    }

    async fn get_request_object(
        &self,
        auth_request: &AuthorisationRequest,
        client: &ClientInformation,
        config: &RequestObjectConfiguration,
    ) -> Result<Option<GenericJWT>> {
        match (
            config.request,
            config.request_uri,
            &auth_request.request,
            &auth_request.request_uri,
        ) {
            (true, _, Some(request_obj), None) => {
                let alg = get_request_object_alg(request_obj)?;
                let keystore = self.keystore_service.server_keystore(client, &alg);
                let jwt = GenericJWT::parse(request_obj, &keystore)
                    .map_err(Error::InvalidRequestObject)?;
                Ok(Some(jwt))
            }
            (_, true, None, Some(request_uri)) => {
                let request_obj = get_object_from_uri(request_uri).await?;
                let alg = get_request_object_alg(&request_obj)?;
                let keystore = self.keystore_service.server_keystore(client, &alg);
                let jwt = GenericJWT::parse(&request_obj, &keystore)
                    .map_err(Error::InvalidRequestObject)?;
                Ok(Some(jwt))
            }
            (_, _, Some(_), Some(_)) => Err(Error::RequestObjAndUri),
            _ => Ok(None),
        }
    }
}

async fn get_object_from_uri(request_uri: &Url) -> Result<String> {
    let request_obj = reqwest::get(request_uri.as_str())
        .await
        .context("Failed to fetch request_obj from uri")?
        .text()
        .await
        .context("Failed to read request_obj from response body")?;
    Ok(request_obj)
}

fn get_request_object_alg(request_obj: &str) -> Result<SigningAlgorithm> {
    GenericJWT::parse_alg(request_obj)
        .map_err(Error::InvalidRequestObject)?
        .ok_or(Error::MissingAlg)
}

fn validate_request_obj_metadata(
    client: &ClientInformation,
    alg: &oidc_types::jose::jws::SigningAlgorithm,
    ro_config: &RequestObjectConfiguration,
) -> Result<()> {
    if let Some(ro_alg) = client.metadata().request_object_signing_alg.as_ref() {
        if *alg != *ro_alg {
            return Err(Error::AlgMismatch(
                alg.name().to_owned(),
                ro_alg.name().to_owned(),
            ));
        }
    }
    if alg.name() == UnsecuredJwsAlgorithm::None.name() && ro_config.require_signed_request_object {
        return Err(Error::UnsignedRequestObject);
    }
    Ok(())
}
