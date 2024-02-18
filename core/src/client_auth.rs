use std::future::Future;

use thiserror::Error;
use x509_parser::error::X509Error;
use x509_parser::nom;
use x509_parser::pem::Pem;

use oidc_types::certificate::CertificateThumbprint;
use oidc_types::client::ClientID;
use oidc_types::jose::error::JWTError;
use oidc_types::jose::jwt2::{SignedJWT, JWT};
use oidc_types::jose::Algorithm;
use oidc_types::secret::{PlainTextSecret, MIN_SECRET_LEN};
use ClientCredential::*;

use crate::client_credentials::{
    ClientSecretCredential, ClientSecretJWTCredential, JWTCredential, PrivateKeyJWTCredential,
    SelfSignedTLSClientAuthCredential, TLSClientAuthCredential,
};
use crate::configuration::OpenIDProviderConfiguration;
use crate::keystore::KeyUse;
use crate::models::client::{AuthenticatedClient, ClientInformation};
use crate::services::keystore::KeystoreService;
use crate::validate_required_claim;

#[derive(Debug, Error)]
pub enum ClientAuthenticationError {
    #[error("Invalid secret {}", .0)]
    InvalidSecret(PlainTextSecret),
    #[error("Cannot authenticate client with the provided certificate")]
    InvalidCertificateAuth,
    #[error("Cannot parse provided certificate to x509 format")]
    InvalidCertificate(#[from] nom::Err<X509Error>),
    #[error("Missing certificate in request. Looked at header: {}", .0)]
    MissingCertificate(&'static str),
    #[error("Invalid authentication method")]
    InvalidAuthMethod,
    #[error("Invalid jwt credential: {:?}, err: {}", .0, .1)]
    InvalidAssertion(SignedJWT, #[source] JWTError),
    #[error("Unable to fetch keystore for user auth")]
    Keystore(#[source] anyhow::Error),
    #[error("Unable to fetch jwk from keystore")]
    Jwk,
    #[error(transparent)]
    Internal(anyhow::Error),
}

pub trait ClientAuthenticator {
    fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> impl Future<Output = Result<AuthenticatedClient, ClientAuthenticationError>> + Send;
}

#[derive(Debug, Clone)]
pub enum ClientCredential {
    ClientSecretBasic(ClientSecretCredential),
    ClientSecretPost(ClientSecretCredential),
    ClientSecretJwt(ClientSecretJWTCredential),
    PrivateKeyJwt(PrivateKeyJWTCredential),
    TlsClientAuth(TLSClientAuthCredential),
    SelfSignedTlsClientAuth(SelfSignedTLSClientAuthCredential),
    None,
}

impl ClientAuthenticator for ClientCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        match self {
            ClientSecretBasic(inner) => {
                inner.authenticate(provider, keystore_service, client).await
            }
            ClientSecretPost(inner) => inner.authenticate(provider, keystore_service, client).await,
            ClientSecretJwt(inner) => inner.authenticate(provider, keystore_service, client).await,
            PrivateKeyJwt(inner) => inner.authenticate(provider, keystore_service, client).await,
            TlsClientAuth(inner) => inner.authenticate(provider, keystore_service, client).await,
            SelfSignedTlsClientAuth(inner) => {
                inner.authenticate(provider, keystore_service, client).await
            }
            None => Ok(AuthenticatedClient::new(client, Option::None)),
        }
    }
}

impl ClientAuthenticator for ClientSecretCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        _keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let (secret, certificate) = self.consume();

        if let Some(client_secret) = client.secret() {
            if secret.len() < MIN_SECRET_LEN || client_secret != secret.as_str() {
                return Err(ClientAuthenticationError::InvalidSecret(secret.into()));
            }
            authenticated_client(provider, client, certificate.as_ref())
        } else {
            Err(ClientAuthenticationError::InvalidAuthMethod)
        }
    }
}

impl ClientAuthenticator for ClientSecretJWTCredential {
    //noinspection DuplicatedCode
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let (jwt_credential, certificate) = self.credential();
        authenticate_client_jwt(
            provider,
            keystore_service,
            client,
            jwt_credential,
            certificate,
        )
        .await
    }
}

impl ClientAuthenticator for PrivateKeyJWTCredential {
    //noinspection DuplicatedCode
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let (jwt_credential, certificate) = self.credential();
        authenticate_client_jwt(
            provider,
            keystore_service,
            client,
            jwt_credential,
            certificate,
        )
        .await
    }
}

impl ClientAuthenticator for TLSClientAuthCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        _keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let mtls_config = provider.mtls();
        let pem = self
            .certificate()
            .ok_or(ClientAuthenticationError::MissingCertificate(
                mtls_config.certificate_header(),
            ))?;
        let cert = pem.parse_x509()?;
        let certificate_validator = mtls_config.certificate_validator();
        if !certificate_validator(&cert, &client) {
            return Err(ClientAuthenticationError::InvalidCertificateAuth);
        }
        Ok(AuthenticatedClient::new(
            client,
            Some(CertificateThumbprint::from(cert)),
        ))
    }
}

impl ClientAuthenticator for SelfSignedTLSClientAuthCredential {
    async fn authenticate(
        self,
        provider: &OpenIDProviderConfiguration,
        keystore_service: &KeystoreService,
        client: ClientInformation,
    ) -> Result<AuthenticatedClient, ClientAuthenticationError> {
        let pem = self
            .certificate()
            .ok_or(ClientAuthenticationError::MissingCertificate(
                provider.mtls().certificate_header(),
            ))?;
        let cert = pem.parse_x509()?;
        let keystore = keystore_service
            .asymmetric_keystore(&client)
            .await
            .map_err(ClientAuthenticationError::Internal)?;
        let thumbprint = CertificateThumbprint::from(cert);
        let key = keystore
            .select(Option::None)
            .thumbprint(&thumbprint)
            .first();
        if key.is_some() {
            Ok(AuthenticatedClient::new(client, Some(thumbprint)))
        } else {
            Err(ClientAuthenticationError::InvalidCertificateAuth)
        }
    }
}

async fn authenticate_client_jwt(
    provider: &OpenIDProviderConfiguration,
    keystore_service: &KeystoreService,
    client: ClientInformation,
    jwt_credential: JWTCredential,
    certificate: Option<Pem>,
) -> Result<AuthenticatedClient, ClientAuthenticationError> {
    let jwt = jwt_credential.assertion();
    let alg = jwt.alg().ok_or_else(|| {
        ClientAuthenticationError::InvalidAssertion(jwt.clone(), JWTError::JWKAlgorithmNotFound)
    })?;
    if let Some(auth_alg) = client.metadata().token_endpoint_auth_signing_alg.as_ref() {
        if alg != *auth_alg {
            return Err(ClientAuthenticationError::InvalidAssertion(
                jwt,
                JWTError::InvalidJWKAlgorithm(format!(
                    "alg header {} differs from the algorithm registered for the client: {}",
                    alg.name(),
                    client.id()
                )),
            ));
        }
    }
    let keystore = keystore_service
        .keystore(&client, &alg)
        .await
        .map_err(ClientAuthenticationError::Keystore)?;
    let key = keystore
        .select(Some(KeyUse::Sig))
        .kid(jwt.kid().map(ToOwned::to_owned))
        .alg(alg.name())
        .first()
        .ok_or(ClientAuthenticationError::Jwk)?;

    jwt.verify(key)
        .map_err(|err| ClientAuthenticationError::InvalidAssertion(jwt.clone(), err))?;

    validate_jwt(provider, jwt, client.id())?;
    authenticated_client(provider, client, certificate.as_ref())
}

fn authenticated_client(
    provider: &OpenIDProviderConfiguration,
    client: ClientInformation,
    certificate: Option<&Pem>,
) -> Result<AuthenticatedClient, ClientAuthenticationError> {
    if client.metadata().tls_client_certificate_bound_access_tokens {
        let pem = certificate.ok_or(ClientAuthenticationError::MissingCertificate(
            provider.mtls().certificate_header(),
        ))?;
        let cert = pem.parse_x509()?;
        Ok(AuthenticatedClient::new(
            client,
            Some(CertificateThumbprint::from(cert)),
        ))
    } else {
        Ok(AuthenticatedClient::new(client, Option::None))
    }
}

fn validate_jwt(
    provider: &OpenIDProviderConfiguration,
    signed_jwt: SignedJWT,
    client_id: ClientID,
) -> Result<(), ClientAuthenticationError> {
    validate_required_claim!(issuer, signed_jwt, client_id);
    validate_required_claim!(subject, signed_jwt, client_id);
    let expected_audience = provider
        .issuer()
        .inner()
        .join(provider.routes().token)
        .map_err(|err| ClientAuthenticationError::Internal(err.into()))?;
    validate_required_claim!(audience, signed_jwt, contains, expected_audience);
    //TODO add checks for jti (uniqueness)
    Ok(())
}

mod macros {
    #[macro_export]
    macro_rules! validate_required_claim {
        (
            $claim_name:ident,
            $jwt:ident,
            $expected:expr
        ) => {
            // Checking if the claim exists
            if let Some(claim_value) = $jwt.payload().$claim_name() {
                if claim_value.as_bytes() != $expected.as_ref() {
                    return Err(ClientAuthenticationError::InvalidAssertion(
                        $jwt.clone(), // Ensure you pass 'signed_jwt' into the macro
                        JWTError::InvalidJwtFormat(format!("Invalid {}", stringify!($claim_name))),
                    ));
                }
            } else {
                return Err(ClientAuthenticationError::InvalidAssertion(
                    $jwt.clone(),
                    JWTError::InvalidJwtFormat(format!("missing {}", stringify!($claim_name))),
                ));
            }
        };

        (
            $claim_name:ident,
            $jwt:ident,
            $contains: ident,
            $expected:expr
        ) => {
            // Checking if the claim exists
            if let Some(claim_value) = $jwt.payload().$claim_name() {
                if !claim_value.$contains(&$expected.as_ref()) {
                    return Err(ClientAuthenticationError::InvalidAssertion(
                        $jwt.clone(), // Ensure you pass 'signed_jwt' into the macro
                        JWTError::InvalidJwtFormat(format!("Invalid {}", stringify!($claim_name))),
                    ));
                }
            } else {
                return Err(ClientAuthenticationError::InvalidAssertion(
                    $jwt.clone(),
                    JWTError::InvalidJwtFormat(format!("missing {}", stringify!($claim_name))),
                ));
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::str::FromStr;

    use x509_parser::der_parser::Oid;
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::pem::Pem;

    const CERT: &str = r#"
-----BEGIN CERTIFICATE-----
MIIHxDCCBaygAwIBAgIIW2DbwXOM3rgwDQYJKoZIhvcNAQELBQAwdzELMAkGA1UE
BhMCQlIxEzARBgNVBAoMCklDUC1CcmFzaWwxNTAzBgNVBAsMLEF1dG9yaWRhZGUg
Q2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjEwMRwwGgYDVQQDDBNBQyBT
RVJBU0EgU1NMIEVWIFYzMB4XDTIyMTIxOTE1MDAwMFoXDTIzMTIxOTE0NTk1OVow
ggFDMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjETMBEGCysGAQQBgjc8
AgEDEwJCUjEXMBUGA1UEBRMONDMxNDI2NjYwMDAxOTcxCzAJBgNVBAYTAkJSMSIw
IAYDVQQKDBlDaGljYWdvIEFkdmlzb3J5IFBhcnRuZXJzMQswCQYDVQQIDAJTUDES
MBAGA1UEBwwJU2FvIFBhdWxvMTMwMQYDVQRhDCpPRkJCUi1kNzM4NGJkMC04NDJm
LTQzYzUtYmUwMi05ZDJiMmQ1ZWZjMmMxNDAyBgoJkiaJk/IsZAEBDCRiYzk3Yjhm
MC1jYWUwLTRmMmYtOTk3OC1kOTNmMGU1NmE4MzMxNzA1BgNVBAMMLndlYi5jb25m
dHBwLmRpcmVjdG9yeS5vcGVuYmFua2luZ2JyYXNpbC5vcmcuYnIwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCufTATS7fS8eP6wUekm0op5/q4/FoJn60D
CirmnuJzQtz3UuZfUPmGPwoyBiDNgLIrmZ9nY6yqWfT1+MUx9Km+x/a1ItmtXehg
O20mqTrUBOj3OzIW5kh76eEmI+O1n1kYXQ5QtqIjRcV3orzdfWnupigzos3sAFgn
Qu6I049HL5Ua1tBmc7cnUo4BXAPrl2PRVfqdmeEFsgElFu6hBce4mJshvYDVvK5L
VI+iAx6PlYBrOrQeEms16kAi93uSfiidMLsyP6Kje4Yj5qvt4fpsMqR2iqlC/fAM
K3cjRS8mfoctdtxfG0VeR0HV4NVZvUcCVE+CDGWdZVbONDvtrq3JAgMBAAGjggKE
MIICgDAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFDBpPcnubSo1CySCrFk9Y1pVK+fF
MIGjBggrBgEFBQcBAQSBljCBkzBNBggrBgEFBQcwAoZBaHR0cDovL3d3dy5jZXJ0
aWZpY2Fkb2RpZ2l0YWwuY29tLmJyL2NhZGVpYXMvc2VyYXNhc3NsZXZ2MTAtMy5w
N2IwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmNlcnRpZmljYWRvZGlnaXRhbC5j
b20uYnIvc2VyYXNhc3NsZXZ2MTAtMzA5BgNVHREEMjAwgi53ZWIuY29uZnRwcC5k
aXJlY3Rvcnkub3BlbmJhbmtpbmdicmFzaWwub3JnLmJyMIGFBgNVHSAEfjB8MAkG
B2BMAQIBgQAwbwYFZ4EMAQEwZjBkBggrBgEFBQcCARZYaHR0cDovL3B1YmxpY2Fj
YW8uY2VydGlmaWNhZG9kaWdpdGFsLmNvbS5ici9yZXBvc2l0b3Jpby9kcGMvZGVj
bGFyYWNhby1zZXJhc2Etc3NsLWV2LnBkZjATBgNVHSUEDDAKBggrBgEFBQcDAjCB
pwYDVR0fBIGfMIGcME+gTaBLhklodHRwOi8vd3d3LmNlcnRpZmljYWRvZGlnaXRh
bC5jb20uYnIvcmVwb3NpdG9yaW8vbGNyL3NlcmFzYXNzbGV2djEwLTMuY3JsMEmg
R6BFhkNodHRwOi8vbGNyLmNlcnRpZmljYWRvcy5jb20uYnIvcmVwb3NpdG9yaW8v
bGNyL3NlcmFzYXNzbGV2djEwLTMuY3JsMB0GA1UdDgQWBBTtgD0BDVtTNJyQm1po
D1kRHzxc9jALBgNVHQ8EBAMCBaAwDQYJKoZIhvcNAQELBQADggIBAGcLWbskRaTD
CbxN6TI8dwz9ZdXATH+oHgdYQuAFyg4U1/aE3i+InbQAGIPLSWBHYMwRymNgXPQd
JyUbh4Q5HVGCCvOqAT6x/iBJ2gA7mNpBWTyUotUm2tuZJyd6yfMcXj2sz9uI3n21
T7+U25n5nFx+h3Zs1VQ8D6Aroz1BCD5b8KF5cWKtzI0OV1QnTICbwV5qBwq5IuBZ
kv9a3yHVB6qDS2lDvBzmdLfyla+/5iZtK0J9APyTBjNm2Rdf4zzzx2JMw0aFdvvX
IC2+ejQKauGRnIXdrJCuC7Vg78K0A/qCxCKk2DKF1Gt5lpY+ZJsdqf1NVBjNyWVb
5GAZIU8pbi0FsWParTpRL98VxHRnnBVLhQoQ36988NS9XD2RB8ywI0+p8Ce3E0Lw
MQHagnBLszslpnKeQgkeuqYfR2QAv3Y1QzyiLflWQCmZqkSF0jlZKuVzlPVDTm9X
BnG5Itaan28+XtToXzNMSgc78fu+6bVJT4eeWuPgWQDFyg1e6/MUU+jlWnvYclvX
k1dPwPNyC/Iy7HUPFk2G3HQGl2HN+Ys6egNEbk4MIwWb2QP9O7JkZHXtkmBfqnaV
XQ3bZpG2gnQ5iD8CrqdshWioTtYtQqFQwPZzgj52ib6YEjJEMTVTe11KJGWFXdbf
DF/HFEAZ0Q/IAVD14+0vtnKa7vkJ1Jgq
-----END CERTIFICATE-----"#;

    #[test]
    fn test_cert_parse() {
        let (pem, _) = Pem::read(Cursor::new(CERT.as_bytes())).expect("Error parsing pem");
        let cert = pem.parse_x509().expect("Error parsing x509");

        let oid = Oid::from_str("2.5.4.97").unwrap();
        println!("{}", cert.subject);
        println!("{}", cert.issuer);
        println!("{}", cert.version);

        for ext in cert.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for gn in &san.general_names {
                    println!("SAN: {}", gn);
                }
            }
        }
    }
}
