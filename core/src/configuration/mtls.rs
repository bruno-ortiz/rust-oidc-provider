use crate::models::client::ClientInformation;
use derive_builder::Builder;
use x509_parser::certificate::X509Certificate;

type CertValidator = fn(X509Certificate, &ClientInformation) -> bool;

#[derive(Debug, Builder)]
#[builder(default)]
pub struct MTLSConfiguration {
    certificate_bound_access_token: bool,
    certificate_header: &'static str,
    validate_cert: CertValidator,
}

impl MTLSConfiguration {
    pub fn certificate_bound_access_token(&self) -> bool {
        self.certificate_bound_access_token
    }
    pub fn certificate_header(&self) -> &'static str {
        self.certificate_header
    }

    pub fn certificate_validator(&self) -> CertValidator {
        self.validate_cert
    }
}

impl Default for MTLSConfiguration {
    fn default() -> Self {
        MTLSConfiguration {
            certificate_bound_access_token: false,
            certificate_header: "X-MTLS-CERTIFICATE",
            validate_cert: unimplemented,
        }
    }
}

fn unimplemented(_cert: X509Certificate, _client: &ClientInformation) -> bool {
    panic!("User should implement this function")
}
