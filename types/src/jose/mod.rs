pub use josekit::jwe::alg::aesgcmkw::AesgcmkwJweAlgorithm::{A128gcmkw, A192gcmkw, A256gcmkw};
pub use josekit::jwe::alg::aeskw::AeskwJweAlgorithm::{A128kw, A192kw, A256kw};
pub use josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm::{
    EcdhEs, EcdhEsA128kw, EcdhEsA192kw, EcdhEsA256kw,
};
pub use josekit::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweAlgorithm::{
    Pbes2Hs256A128kw, Pbes2Hs384A192kw, Pbes2Hs512A256kw,
};
pub use josekit::jwe::alg::rsaes::RsaesJweAlgorithm::{
    RsaOaep, RsaOaep256, RsaOaep384, RsaOaep512,
};
pub use josekit::jwe::enc::*;
use josekit::jwk::Jwk;
use josekit::jws::JwsHeader;
pub use josekit::jws::*;

pub mod error;
pub mod jwe;
pub mod jwk_ext;
pub mod jwk_set;
pub mod jws;
pub mod jwt2;

pub trait JwsHeaderExt {
    fn from_key(key: &Jwk) -> Self;
}

impl JwsHeaderExt for JwsHeader {
    fn from_key(key: &Jwk) -> Self {
        let alg = key
            .algorithm()
            .expect("Signing key must have an  algorithm");
        let mut header = JwsHeader::new();
        if let Some(kid) = key.key_id() {
            header.set_key_id(kid);
        }
        header.set_token_type("JWT");
        header.set_algorithm(alg);
        header
    }
}
