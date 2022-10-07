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
pub use josekit::jws::*;
use josekit::jwt::JwtPayload;
use serde_json::Value;
use std::collections::HashMap;

pub mod error;
pub mod jwe;
pub mod jwk_ext;
pub mod jwk_set;
pub mod jws;
pub mod jwt2;

pub trait Algorithm {
    fn is_symmetric(&self) -> bool;
}

pub trait JwtPayloadExt {
    fn from_hash_map(map: HashMap<&str, Value>) -> JwtPayload;
}

impl JwtPayloadExt for JwtPayload {
    fn from_hash_map(map: HashMap<&str, Value>) -> JwtPayload {
        let mut payload = JwtPayload::new();
        for (k, v) in map {
            payload
                .set_claim(k, Some(v))
                .expect("Unexpected err setting claim");
        }
        payload
    }
}
