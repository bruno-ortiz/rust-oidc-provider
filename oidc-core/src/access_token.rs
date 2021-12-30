

use crate::hash::Hashable;


#[derive(Debug)]
pub struct AccessToken(String);

impl Hashable for AccessToken {
    fn identifier(&self) -> &str {
        &self.0
    }
}
