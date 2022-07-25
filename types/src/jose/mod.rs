use josekit::jwk::Jwk;
use josekit::jws::JwsHeader;

pub mod error;
pub mod jwe;
pub mod jwk_set;
pub mod jws;
pub mod jwt;

pub trait JwsHeaderExt {
    fn from_key(key: &Jwk) -> Self;
}

impl JwsHeaderExt for JwsHeader {
    fn from_key(key: &Jwk) -> Self {
        let alg = key
            .algorithm()
            .expect("Signing key must have an  algorithm");
        let kid = key.key_id().expect("Signing key must have a kid");
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_algorithm(alg);
        header.set_key_id(kid);
        header
    }
}
