use crate::jose::jwt::JWT;
use crate::url_encodable::UrlEncodable;
use indexmap::IndexMap;
use josekit::jwt::JwtPayload;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdToken(JWT);

impl IdToken {
    pub fn new(inner: JWT) -> Self {
        Self(inner)
    }

    pub fn payload(&self) -> &JwtPayload {
        self.0.payload()
    }

    pub fn serialized(self) -> String {
        self.0.serialize_owned()
    }
}

impl UrlEncodable for IdToken {
    fn params(self) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        map.insert("id_token".to_owned(), self.serialized());
        map
    }
}
