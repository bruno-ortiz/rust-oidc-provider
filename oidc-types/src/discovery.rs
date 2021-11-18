use crate::auth_method::AuthMethod;
use crate::claim_type::ClaimType;
use crate::grant_type::GrantType;
use crate::issuer::Issuer;
use crate::jose::algorithm::Algorithm;
use crate::pkce::CodeChallengeMethod;
use crate::response_mode::ResponseMode;
use crate::response_type::ResponseTypeValue;
use crate::scopes::Scope;
use crate::subject_type::SubjectType;
use url::Url;

pub struct OIDCProviderMetadata {
    pub issuer: Issuer,
    pub authorization_endpoint: Url,
    pub end_session_endpoint: Url,
    pub registration_endpoint: Url,
    pub revocation_endpoint: Url,
    pub introspection_endpoint: Url,
    pub token_endpoint: Url,
    pub userinfo_endpoint: Url,
    pub jwks_uri: Url,
    pub response_types_supported: Vec<ResponseTypeValue>,
    pub scopes_supported: Vec<Scope>,
    pub claims_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<CodeChallengeMethod>,
    pub grant_types_supported: Vec<GrantType>,
    pub response_modes_supported: Vec<ResponseMode>,
    pub id_token_signing_alg_values_supported: Vec<Algorithm>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<Algorithm>,
    pub request_object_signing_alg_values_supported: Vec<Algorithm>,
    pub userinfo_signing_alg_values_supported: Vec<Algorithm>,
    pub authorization_signing_alg_values_supported: Vec<Algorithm>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Vec<Algorithm>,
    pub revocation_endpoint_auth_signing_alg_values_supported: Vec<Algorithm>,
    pub token_endpoint_auth_methods_supported: Vec<AuthMethod>,
    pub subject_types_supported: Vec<SubjectType>,
    pub introspection_endpoint_auth_methods_supported: Vec<AuthMethod>,
    pub revocation_endpoint_auth_methods_supported: Vec<AuthMethod>,
    pub claim_types_supported: Vec<ClaimType>,
    pub claims_parameter_supported: bool,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub require_request_uri_registration: bool,
    pub tls_client_certificate_bound_access_tokens: bool,
}
