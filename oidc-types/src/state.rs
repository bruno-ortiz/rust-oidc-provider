use serde::Deserialize;
use crate::hash::Hashable;

#[derive(Debug, Clone, Deserialize)]
pub struct State(String);

impl Hashable for State {
    fn identifier(&self) -> &str {
        &self.0
    }
}
