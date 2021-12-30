use crate::hash::Hashable;

#[derive(Debug, Clone)]
pub struct State(String);

impl Hashable for State {
    fn identifier(&self) -> &str {
        &self.0
    }
}
