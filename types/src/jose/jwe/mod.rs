use josekit::jwe::JweHeader;
use josekit::jwk::Jwk;

pub mod alg;
pub mod enc;

pub trait JweHeaderExt {
    fn from_key(key: &Jwk, enc: impl Into<String>, is_nested: bool) -> Self;
}

impl JweHeaderExt for JweHeader {
    fn from_key(key: &Jwk, enc: impl Into<String>, is_nested: bool) -> Self {
        let alg = key
            .algorithm()
            .expect("Signing key must have an  algorithm");
        let mut header = JweHeader::new();
        if let Some(kid) = key.key_id() {
            header.set_key_id(kid);
        }
        header.set_token_type("JWT");
        if is_nested {
            header.set_content_type("JWT");
        }
        header.set_algorithm(alg);
        header.set_content_encryption(enc);
        header
    }
}
