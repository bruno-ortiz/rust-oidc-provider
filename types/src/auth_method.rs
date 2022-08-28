use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    ClientSecretJwt,
    PrivateKeyJwt,
    TlsClientAuth,
    SelfSignedTlsClientAuth,
    None,
}

impl Display for AuthMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::ClientSecretBasic => write!(f, "client_secret_basic"),
            AuthMethod::ClientSecretPost => write!(f, "client_secret_post"),
            AuthMethod::ClientSecretJwt => write!(f, "client_secret_jwt"),
            AuthMethod::PrivateKeyJwt => write!(f, "private_key_jwt"),
            AuthMethod::TlsClientAuth => write!(f, "tls_client_auth"),
            AuthMethod::SelfSignedTlsClientAuth => write!(f, "self_signed_tls_client_auth"),
            AuthMethod::None => write!(f, "none"),
        }
    }
}
