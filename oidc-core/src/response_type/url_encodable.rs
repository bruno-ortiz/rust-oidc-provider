

pub trait UrlEncodable {
    fn key(&self) -> String;
    fn value(&self) -> String;
}
