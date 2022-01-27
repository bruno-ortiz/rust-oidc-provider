#[derive(Debug, Clone)]
pub struct Subject(String);

impl AsRef<str> for Subject {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
