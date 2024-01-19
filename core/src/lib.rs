mod adapter;
pub mod authorisation_request;
mod claims;
pub mod client;
pub mod client_auth;
pub mod client_credentials;
pub mod configuration;
pub mod context;
pub mod error;
pub mod grant_type;
pub mod hash;
pub mod id_token;
pub mod id_token_builder;
mod jwt;
pub mod keystore;
pub mod models;
mod pairwise;
pub mod profile;
mod prompt;
pub mod request_object;
pub mod response_mode;
pub mod response_type;
pub mod services;
pub mod session;
pub mod user;
pub mod userinfo;
mod utils;

mod macros {
    macro_rules! true_or_return {
        ($i:ident = $e:expr) => {
            $i = $e;
            if !$i {
                return $i;
            }
        };
    }
    pub(crate) use true_or_return;
}
