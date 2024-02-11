use std::collections::HashMap;

pub use josekit::jwe::alg::aesgcmkw::AesgcmkwJweAlgorithm::{A128gcmkw, A192gcmkw, A256gcmkw};
pub use josekit::jwe::alg::aeskw::AeskwJweAlgorithm::{A128kw, A192kw, A256kw};
pub use josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm::{
    EcdhEs, EcdhEsA128kw, EcdhEsA192kw, EcdhEsA256kw,
};
pub use josekit::jwe::alg::rsaes::RsaesJweAlgorithm::{
    RsaOaep, RsaOaep256, RsaOaep384, RsaOaep512,
};
pub use josekit::jwe::enc::*;
pub use josekit::jws::*;
pub use josekit::jwt::alg::unsecured::UnsecuredJwsAlgorithm;
use josekit::jwt::JwtPayload;
use serde_json::Value;

pub mod error;
pub mod jwe;
pub mod jwk_ext;
pub mod jwk_set;
pub mod jws;
pub mod jwt2;

pub trait Algorithm {
    fn is_symmetric(&self) -> bool;

    fn name(&self) -> &str;
}

pub trait SizableAlgorithm: Algorithm {
    fn length(&self) -> Option<usize>;
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
