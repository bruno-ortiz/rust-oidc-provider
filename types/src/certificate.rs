use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use derive_more::{Display, Into};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use x509_parser::certificate::X509Certificate;

#[derive(Debug, Clone, Eq, PartialEq, Into, Display, Serialize, Deserialize)]
pub struct CertificateThumbprint(String);

impl CertificateThumbprint {
    pub fn new(value: String) -> Self {
        Self(value)
    }
}

impl From<X509Certificate<'_>> for CertificateThumbprint {
    fn from(value: X509Certificate) -> Self {
        let thumbprint = cert_thumbprint(&value);
        CertificateThumbprint(thumbprint)
    }
}

impl PartialEq<String> for CertificateThumbprint {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

fn cert_thumbprint(cert: &X509Certificate) -> String {
    let cert_digest = sha2::Sha256::digest(cert.as_ref());
    BASE64_URL_SAFE_NO_PAD.encode(cert_digest)
}
