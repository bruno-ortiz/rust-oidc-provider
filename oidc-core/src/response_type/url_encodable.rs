use std::collections::HashMap;

pub trait UrlEncodable {
    fn params(&self) -> HashMap<String, String>;
}
