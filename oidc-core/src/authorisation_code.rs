use crate::hash::Hashable;
use crate::response_type::UrlEncodable;

#[derive(Debug)]
pub struct AuthorisationCode(pub(crate) String);

impl Hashable for AuthorisationCode {
    fn identifier(&self) -> &str {
        &self.0
    }
}
