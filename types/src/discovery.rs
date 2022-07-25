use crate::claim_type::ClaimType;
use crate::grant_type::GrantType;
use crate::issuer::Issuer;
use crate::jose::jwe::alg::EncryptionAlgorithm;
use crate::jose::jwe::enc::ContentEncryptionAlgorithm;
use crate::jose::jws::Algorithm;
use crate::pkce::CodeChallengeMethod;
use crate::response_mode::ResponseMode;
use crate::response_type::ResponseType;
use crate::scopes::Scope;
use crate::subject_type::SubjectType;
use derive_builder::Builder;
use serde::Serialize;
use serde_with::skip_serializing_none;
use url::Url;

#[skip_serializing_none]
#[derive(Serialize, Builder)]
pub struct OIDCProviderMetadata {
    issuer: Issuer,
    authorization_endpoint: Url,
    response_types_supported: Vec<ResponseType>,
    scopes_supported: Vec<Scope>,
    jwks_uri: Url,
    code_challenge_methods_supported: Vec<CodeChallengeMethod>,
    grant_types_supported: Vec<GrantType>,
    response_modes_supported: Vec<ResponseMode>,
    id_token_signing_alg_values_supported: Vec<Algorithm>,
    id_token_encryption_alg_values_supported: Option<Vec<EncryptionAlgorithm>>,
    id_token_encryption_enc_values_supported: Option<Vec<ContentEncryptionAlgorithm>>,
    request_object_signing_alg_values_supported: Vec<Algorithm>,
    request_object_encryption_alg_values_supported: Option<Vec<EncryptionAlgorithm>>,
    request_object_encryption_enc_values_supported: Option<Vec<ContentEncryptionAlgorithm>>,
    authorization_signing_alg_values_supported: Option<Vec<Algorithm>>,
    authorization_encryption_alg_values_supported: Option<Vec<EncryptionAlgorithm>>,
    authorization_encryption_enc_values_supported: Option<Vec<ContentEncryptionAlgorithm>>,
    subject_types_supported: Vec<SubjectType>,
    claims_supported: Vec<String>,
    claim_types_supported: Option<Vec<ClaimType>>,
    claims_parameter_supported: bool,
    request_parameter_supported: bool,
    request_uri_parameter_supported: bool,
    require_request_uri_registration: bool,
    tls_client_certificate_bound_access_tokens: bool,
}

/*
TODO: implement session management
end_session_endpoint: Url,
check_session_iframe:Url,
--------------------------------------
TODO: implement DCR/DCM (RFC 7591, RFC 7592)
registration_endpoint: Url,
--------------------------------------
TODO: enable this metadata when token endpoints is enabled
token_endpoint: Url,
token_endpoint_auth_signing_alg_values_supported: Vec<Algorithm>,
token_endpoint_auth_methods_supported: Vec<AuthMethod>,
revocation_endpoint: Option<Url>,
revocation_endpoint_auth_signing_alg_values_supported: Vec<Algorithm>,
revocation_endpoint_auth_methods_supported: Vec<AuthMethod>,
introspection_endpoint: Url,
introspection_endpoint_auth_signing_alg_values_supported: Vec<Algorithm>,
introspection_endpoint_auth_methods_supported: Vec<AuthMethod>,
TODO: implement userinfo
userinfo_endpoint: Url,
userinfo_signing_alg_values_supported: Vec<Algorithm>,
*/
