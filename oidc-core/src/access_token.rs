use oidc_types::jose::jwt::JWT;

use crate::hash::Hashable;
use crate::response_type::UrlEncodable;

#[derive(Debug)]
pub struct AccessToken(String);

impl Hashable for AccessToken {
    fn identifier(&self) -> &str {
        &self.0
    }
}
