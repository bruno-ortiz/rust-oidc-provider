use crate::hash::Hashable;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct State(String);

impl Hashable for State {
    fn identifier(&self) -> &str {
        &self.0
    }
}
