use josekit::jwt::alg::unsecured::UnsecuredJwsAlgorithm;
use url::Url;

use oidc_types::jose::error::JWTError;
use oidc_types::jose::jwt2::JWT;

use crate::authorisation_request::AuthorisationRequest;
use crate::configuration::request_object::RequestObjectConfiguration;
use crate::configuration::OpenIDProviderConfiguration;
use crate::error::OpenIdError;
use crate::id_token_builder::JwtPayloadExt;
use crate::jwt::{GenericJWT, ValidJWT};
use crate::models::client::ClientInformation;
use crate::utils::get_jose_algorithm;

pub struct RequestObjectProcessor;

impl RequestObjectProcessor {
    pub async fn process(
        request: &AuthorisationRequest,
        client: &ClientInformation,
        configuration: &OpenIDProviderConfiguration,
    ) -> Result<Option<AuthorisationRequest>, OpenIdError> {
        let ro_config = configuration.request_object();
        if let Some(request_obj) = get_request_object(request, client, ro_config).await? {
            let alg = request_obj.alg().ok_or(OpenIdError::invalid_request(
                "Missing alg in request_object Header",
            ))?;
            if alg.name() == UnsecuredJwsAlgorithm::None.name()
                && ro_config.require_signed_request_object
            {
                Err(OpenIdError::invalid_request(
                    "Request object must be signed",
                ))
            } else {
                let keystore = client
                    .keystore(&alg)
                    .await
                    .map_err(OpenIdError::server_error)?;
                let validated = ValidJWT::validate(request_obj, &keystore)
                    .map_err(|err| OpenIdError::invalid_request(err.to_string()))?;
                let authorisation_request = validated
                    .payload()
                    .convert::<AuthorisationRequest>()
                    .map_err(OpenIdError::server_error)?;
                Ok(Some(authorisation_request))
            }
        } else {
            Ok(None)
        }
    }
}

async fn get_request_object(
    auth_request: &AuthorisationRequest,
    client: &ClientInformation,
    config: &RequestObjectConfiguration,
) -> Result<Option<GenericJWT>, OpenIdError> {
    match (
        config.request,
        config.request_uri,
        &auth_request.request,
        &auth_request.request_uri,
    ) {
        (true, _, Some(request_obj), None) => {
            let alg = get_jose_algorithm(request_obj)
                .map_err(parse_err)?
                .ok_or_else(missing_alg)?;
            let keystore = client.server_keystore(&alg);
            let jwt = GenericJWT::parse(request_obj, &keystore).map_err(parse_err)?;
            Ok(Some(jwt))
        }
        (_, true, None, Some(request_uri)) => {
            let request_obj = get_object_from_uri(request_uri).await?;
            let alg = get_jose_algorithm(&request_obj)
                .map_err(parse_err)?
                .ok_or_else(missing_alg)?;
            let keystore = client.server_keystore(&alg);
            let jwt = GenericJWT::parse(&request_obj, &keystore).map_err(parse_err)?;
            Ok(Some(jwt))
        }
        (_, _, Some(_), Some(_)) => Err(request_obj_err()),
        _ => Ok(None),
    }
}

async fn get_object_from_uri(request_uri: &Url) -> Result<String, OpenIdError> {
    let request_obj = reqwest::get(request_uri.as_str())
        .await
        .map_err(OpenIdError::server_error)?
        .text()
        .await
        .map_err(OpenIdError::server_error)?;
    Ok(request_obj)
}

fn parse_err(err: JWTError) -> OpenIdError {
    OpenIdError::invalid_request_with_source("Unable to parse request object", err)
}

fn request_obj_err() -> OpenIdError {
    OpenIdError::invalid_request("Invalid request, authorization request should not provide both request and request_uri parameter")
}

fn missing_alg() -> OpenIdError {
    OpenIdError::invalid_request("Invalid request object: Missing alg in header")
}
